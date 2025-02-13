package planner

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1/plan"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/rke2"
	capicontrollers "github.com/rancher/rancher/pkg/generated/controllers/cluster.x-k8s.io/v1beta1"
	corecontrollers "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/pkg/generic"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
)

const (
	NoAgentPlanStatusMessage = "waiting for agent to check in and apply initial plan"
	WaitingPlanStatusMessage = "waiting for plan to be applied"
	FailedPlanStatusMessage  = "failure while applying plan"
)

type PlanStore struct {
	secrets      corecontrollers.SecretClient
	secretsCache corecontrollers.SecretCache
	machineCache capicontrollers.MachineCache
}

func NewStore(secrets corecontrollers.SecretController, machineCache capicontrollers.MachineCache) *PlanStore {
	return &PlanStore{
		secrets:      secrets,
		secretsCache: secrets.Cache(),
		machineCache: machineCache,
	}
}

// onlyRKE returns a subset of the passed in slice of CAPI machines that only contains machines that have an RKEBootstrap
func onlyRKE(machines []*capi.Machine) (result []*capi.Machine) {
	for _, m := range machines {
		if !isRKEBootstrap(m) {
			continue
		}
		result = append(result, m)
	}
	return
}

// ClusterHasBeenBootstrapped determines if a cluster has undergone the bootstrapping process
// by assessing the value of the joinURL. the control plane joinURL is generated during the bootstrapping process,
// and its existence implies the creation of the cluster at some point in time.
// Caution: there does exist a small window of time in which the joinURL has not been set, but the bootstrap node is up.
func (p *PlanStore) ClusterHasBeenBootstrapped(plan *plan.Plan) bool {
	return getControlPlaneJoinURL(plan) != ""
}

// Load takes a clusters.cluster.x-k8s.io object and the corresponding rkecontrolplanes.rke.cattle.io object and
// generates a new plan.Plan, a bool that indicates whether any plan has been delivered to any of the machines,
// and an error
func (p *PlanStore) Load(cluster *capi.Cluster, rkeControlPlane *rkev1.RKEControlPlane) (*plan.Plan, bool, error) {
	result := &plan.Plan{
		Nodes:    map[string]*plan.Node{},
		Machines: map[string]*capi.Machine{},
		Metadata: map[string]*plan.Metadata{},
	}

	var anyPlanDelivered bool

	machines, err := p.machineCache.List(cluster.Namespace, labels.SelectorFromSet(map[string]string{
		capi.ClusterLabelName: cluster.Name,
	}))
	if err != nil {
		return nil, anyPlanDelivered, err
	}

	machines = onlyRKE(machines)

	secrets, err := p.getPlanSecrets(machines)
	if err != nil {
		return nil, anyPlanDelivered, err
	}

	for _, machine := range machines {
		result.Machines[machine.Name] = machine
	}

	for machineName, secret := range secrets {
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		result.Metadata[machineName] = &plan.Metadata{
			Labels:      secret.Labels,
			Annotations: secret.Annotations,
		}
		node, err := SecretToNode(secret)
		if err != nil {
			return nil, anyPlanDelivered, err
		}
		if node == nil {
			continue
		}
		if node.PlanDataExists {
			anyPlanDelivered = true
		}
		if err := p.setMachineJoinURL(&planEntry{Machine: result.Machines[machineName], Metadata: result.Metadata[machineName], Plan: node}, cluster, rkeControlPlane); err != nil {
			return nil, anyPlanDelivered, err
		}
		result.Nodes[machineName] = node
	}

	return result, anyPlanDelivered, nil
}

func noPlanMessage(entry *planEntry) string {
	if isEtcd(entry) {
		return "waiting for bootstrap etcd to be available"
	} else if isControlPlane(entry) {
		return "waiting for etcd to be available"
	} else {
		return "waiting for control plane to be available"
	}
}

func probesMessage(plan *plan.Node) string {
	var (
		unhealthy []string
	)
	for name, probe := range plan.ProbeStatus {
		if !probe.Healthy {
			unhealthy = append(unhealthy, name)
		}
	}
	sort.Strings(unhealthy)
	return "waiting for probes: " + strings.Join(unhealthy, ", ")
}

func getPlanStatusReasonMessage(entry *planEntry) string {
	switch {
	case entry.Plan == nil:
		return noPlanMessage(entry)
	case len(entry.Plan.Plan.Instructions) == 0:
		return noPlanMessage(entry)
	case entry.Plan.AppliedPlan == nil:
		return NoAgentPlanStatusMessage
	case entry.Plan.Plan.Error != "":
		return entry.Plan.Plan.Error
	case !entry.Plan.Healthy:
		return probesMessage(entry.Plan)
	case entry.Plan.InSync:
		return ""
	case entry.Plan.Failed:
		return FailedPlanStatusMessage
	default:
		return WaitingPlanStatusMessage
	}
}

// SecretToNode consumes a secret of type rke.cattle.io/machine-plan and returns a node object and an error if one exists
func SecretToNode(secret *corev1.Secret) (*plan.Node, error) {
	if secret == nil {
		return nil, fmt.Errorf("unable to convert secret to node plan, secret was nil")
	}
	if secret.Type != rke2.SecretTypeMachinePlan {
		return nil, fmt.Errorf("secret %s/%s was not type %s", secret.Namespace, secret.Name, rke2.SecretTypeMachinePlan)
	}
	result := &plan.Node{
		Healthy: true,
	}
	planData := secret.Data["plan"]
	result.PlanDataExists = len(secret.Data["plan"]) != 0
	appliedPlanData := secret.Data["appliedPlan"]
	failedChecksum := string(secret.Data["failed-checksum"])
	output := secret.Data["applied-output"]
	appliedPeriodicOutput := secret.Data["applied-periodic-output"]
	probes := secret.Data["probe-statuses"]
	failureCount := secret.Data["failure-count"]

	if len(failureCount) > 0 && PlanHash(planData) == failedChecksum {
		failureCount, err := strconv.Atoi(string(failureCount))
		if err != nil {
			return nil, err
		}
		if failureCount > 0 {
			result.Failed = true
			// failure-threshold is set by Rancher when the plan is updated. If it is not set, then it essentially
			// defaults to 1, and any failure causes the plan to be marked as failed
			rawFailureThreshold := secret.Data["failure-threshold"]
			if len(rawFailureThreshold) > 0 {
				failureThreshold, err := strconv.Atoi(string(rawFailureThreshold))
				if err != nil {
					return nil, err
				}
				if failureCount < failureThreshold || failureThreshold == -1 {
					// the plan hasn't actually failed to be applied because we haven't passed the failure threshold or failure threshold is set to -1.
					result.Failed = false
				}
			}
		}
	}

	if len(probes) > 0 {
		result.ProbeStatus = map[string]plan.ProbeStatus{}
		if err := json.Unmarshal(probes, &result.ProbeStatus); err != nil {
			return nil, err
		}
		for _, status := range result.ProbeStatus {
			if !status.Healthy {
				result.Healthy = false
			}
		}
	}

	if len(planData) > 0 {
		if err := json.Unmarshal(planData, &result.Plan); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}

	if len(appliedPlanData) > 0 {
		newPlan := &plan.NodePlan{}
		if err := json.Unmarshal(appliedPlanData, newPlan); err != nil {
			return nil, err
		}
		result.AppliedPlan = newPlan
	}

	if len(output) > 0 {
		gz, err := gzip.NewReader(bytes.NewBuffer(output))
		if err != nil {
			return nil, err
		}
		output, err = io.ReadAll(gz)
		if err != nil {
			return nil, err
		}
		result.Output = map[string][]byte{}
		if err := json.Unmarshal(output, &result.Output); err != nil {
			return nil, err
		}
	}

	if len(appliedPeriodicOutput) > 0 {
		gz, err := gzip.NewReader(bytes.NewBuffer(appliedPeriodicOutput))
		if err != nil {
			return nil, err
		}
		output, err = io.ReadAll(gz)
		if err != nil {
			return nil, err
		}
		result.PeriodicOutput = map[string]plan.PeriodicInstructionOutput{}
		if err := json.Unmarshal(output, &result.PeriodicOutput); err != nil {
			return nil, err
		}
	}

	result.InSync = result.Healthy && bytes.Equal(planData, appliedPlanData)
	return result, nil
}

func PlanHash(plan []byte) string {
	result := sha256.Sum256(plan)
	return hex.EncodeToString(result[:])
}

// getPlanSecrets retrieves the plan secrets for the given list of machines
func (p *PlanStore) getPlanSecrets(machines []*capi.Machine) (map[string]*corev1.Secret, error) {
	result := map[string]*corev1.Secret{}
	for _, machine := range machines {
		secret, err := p.getPlanSecretFromMachine(machine)
		if apierror.IsNotFound(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if secret != nil {
			result[machine.Name] = secret.DeepCopy()
		}
	}

	return result, nil
}

func isRKEBootstrap(machine *capi.Machine) bool {
	return machine.Spec.Bootstrap.ConfigRef != nil &&
		machine.Spec.Bootstrap.ConfigRef.Kind == "RKEBootstrap"
}

// getPlanSecretFromMachine returns the plan secret from the secrets client for the given machine,
// or an error if the plan secret is not available. Notably we do not use the secretsCache to ensure we only operate
// on the latest version of a machine plan secret.
func (p *PlanStore) getPlanSecretFromMachine(machine *capi.Machine) (*corev1.Secret, error) {
	if machine == nil {
		return nil, fmt.Errorf("machine was nil")
	}

	if !isRKEBootstrap(machine) {
		return nil, fmt.Errorf("machine %s/%s is not using RKEBootstrap", machine.Namespace, machine.Name)
	}

	if machine.Spec.Bootstrap.ConfigRef == nil {
		return nil, fmt.Errorf("machine %s/%s bootstrap configref was nil", machine.Namespace, machine.Name)
	}

	if machine.Spec.Bootstrap.ConfigRef.Name == "" {
		return nil, fmt.Errorf("machine %s/%s bootstrap configref name was empty", machine.Namespace, machine.Name)
	}

	secret, err := p.secrets.Get(machine.Namespace, rke2.PlanSecretFromBootstrapName(machine.Spec.Bootstrap.ConfigRef.Name), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	if secret.Type != rke2.SecretTypeMachinePlan {
		return nil, fmt.Errorf("retrieved secret %s/%s type %s did not match expected type %s", secret.Namespace, secret.Name, secret.Type, rke2.SecretTypeMachinePlan)
	}

	return secret, nil
}

// UpdatePlan should not be called directly as it will not block further progress if the plan is not in sync
// maxFailures is the number of attempts the system-agent will make to run the plan (in a failed state). failureThreshold is used to determine when the plan has failed.
func (p *PlanStore) UpdatePlan(entry *planEntry, newNodePlan plan.NodePlan, maxFailures, failureThreshold int) error {
	if maxFailures < failureThreshold && failureThreshold != -1 && maxFailures != -1 {
		return fmt.Errorf("failureThreshold (%d) cannot be greater than maxFailures (%d)", failureThreshold, maxFailures)
	}
	secret, err := p.getPlanSecretFromMachine(entry.Machine)
	if err != nil {
		return err
	}

	data, err := json.Marshal(newNodePlan)
	if err != nil {
		return err
	}

	secret = secret.DeepCopy()
	if secret.Data == nil {
		// Create the map with enough storage for what is needed.
		secret.Data = make(map[string][]byte, 6)
	}

	rke2.CopyPlanMetadataToSecret(secret, entry.Metadata)

	// If the plan is being updated, then delete the probe-statuses so their healthy status will be reported as healthy only when they pass.
	delete(secret.Data, "probe-statuses")

	secret.Data["plan"] = data
	if maxFailures > 0 || maxFailures == -1 {
		secret.Data["max-failures"] = []byte(strconv.Itoa(maxFailures))
	} else {
		delete(secret.Data, "max-failures")
	}

	if failureThreshold > 0 || failureThreshold == -1 {
		secret.Data["failure-threshold"] = []byte(strconv.Itoa(failureThreshold))
	} else {
		delete(secret.Data, "failure-threshold")
	}

	updatedSecret, err := p.secrets.Update(secret)
	if err != nil {
		return err
	}

	// Update the node immediately so that future plan processing occurs
	newNode, err := SecretToNode(updatedSecret)
	if err != nil {
		return err
	}

	entry.Plan = newNode
	return nil
}

func (p *PlanStore) updatePlanSecretLabelsAndAnnotations(entry *planEntry) error {
	secret, err := p.getPlanSecretFromMachine(entry.Machine)
	if err != nil {
		return err
	}

	secret = secret.DeepCopy()
	rke2.CopyPlanMetadataToSecret(secret, entry.Metadata)

	_, err = p.secrets.Update(secret)
	return err
}

// removePlanSecretLabel removes a label with the given key from the plan secret that corresponds to the RKEBootstrap
func (p *PlanStore) removePlanSecretLabel(entry *planEntry, key string) error {
	secret, err := p.getPlanSecretFromMachine(entry.Machine)
	if err != nil {
		return err
	}

	if _, ok := secret.Labels[key]; !ok {
		return nil
	}

	secret = secret.DeepCopy()
	delete(secret.Labels, key)
	_, err = p.secrets.Update(secret)
	return err
}

// assignAndCheckPlan assigns the given newPlan to the designated server in the planEntry, and will return nil if the plan is assigned and in sync.
func assignAndCheckPlan(store *PlanStore, msg string, entry *planEntry, newPlan plan.NodePlan, failureThreshold, maxRetries int) error {
	if entry.Plan == nil || !equality.Semantic.DeepEqual(entry.Plan.Plan, newPlan) {
		if err := store.UpdatePlan(entry, newPlan, failureThreshold, maxRetries); err != nil {
			return err
		}
		return errWaiting(fmt.Sprintf("starting %s", msg))
	}
	if entry.Plan.Failed {
		return fmt.Errorf("operation %s failed", msg)
	}
	if !entry.Plan.InSync {
		return errWaiting(fmt.Sprintf("waiting for %s", msg))
	}
	return nil
}

func (p *PlanStore) setMachineJoinURL(entry *planEntry, capiCluster *capi.Cluster, rkeControlPlane *rkev1.RKEControlPlane) error {
	var (
		err     error
		joinURL string
	)

	if IsEtcdOnlyInitNode(entry) {
		joinURL, err = getJoinURLFromOutput(entry, capiCluster, rkeControlPlane)
		if err != nil || joinURL == "" {
			return err
		}
	} else {
		if entry.Machine.Status.NodeInfo == nil {
			return nil
		}

		address := ""
		for _, machineAddress := range entry.Machine.Status.Addresses {
			switch machineAddress.Type {
			case capi.MachineInternalIP:
				address = machineAddress.Address
			case capi.MachineExternalIP:
				if address == "" {
					address = machineAddress.Address
				}
			}
		}

		joinURL = joinURLFromAddress(address, rke2.GetRuntimeSupervisorPort(rkeControlPlane.Spec.KubernetesVersion))
	}

	if joinURL != "" && entry.Metadata.Annotations[rke2.JoinURLAnnotation] != joinURL {
		entry.Metadata.Annotations[rke2.JoinURLAnnotation] = joinURL
		if err := p.updatePlanSecretLabelsAndAnnotations(entry); err != nil {
			return err
		}

		return generic.ErrSkip
	}

	return nil
}

func joinURLFromAddress(address string, port int) string {
	// ipv6 addresses need to be enclosed in brackets in URLs, and hostnames will fail to be parsed as IPs
	if net.ParseIP(address) != nil && strings.Count(address, ":") >= 2 {
		if !strings.HasPrefix(address, "[") && !strings.HasSuffix(address, "]") {
			address = fmt.Sprintf("[%s]", address)
		}
	}
	return fmt.Sprintf("https://%s:%d", address, port)
}

func getJoinURLFromOutput(entry *planEntry, capiCluster *capi.Cluster, rkeControlPlane *rkev1.RKEControlPlane) (string, error) {
	if entry.Plan == nil || !IsEtcdOnlyInitNode(entry) || capiCluster.Spec.ControlPlaneRef == nil || rkeControlPlane == nil {
		return "", nil
	}

	var address []byte
	var name string
	if ca := entry.Plan.PeriodicOutput[captureAddressInstructionName]; ca.ExitCode != 0 || ca.LastSuccessfulRunTime == "" {
		return "", nil
	} else if etcdNameOutput := entry.Plan.PeriodicOutput[etcdNameInstructionName]; etcdNameOutput.ExitCode != 0 || etcdNameOutput.LastSuccessfulRunTime == "" {
		return "", nil
	} else {
		address = ca.Stdout
		name = string(bytes.TrimSpace(etcdNameOutput.Stdout))
	}

	var str string
	scanner := bufio.NewScanner(bytes.NewBuffer(address))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "{") {
			str = line
			break
		}
	}

	if str == "" {
		return "", nil
	}

	dbInfo := &dbinfo{}
	if err := json.Unmarshal([]byte(str), dbInfo); err != nil {
		return "", err
	}

	for _, member := range dbInfo.Members {
		if member.Name != name {
			continue
		}

		u, err := url.Parse(member.ClientURLs[0])
		if err != nil {
			return "", err
		}

		joinURL := joinURLFromAddress(u.Hostname(), rke2.GetRuntimeSupervisorPort(rkeControlPlane.Spec.KubernetesVersion))
		return joinURL, nil
	}

	// No need to error here because once the plan secret is updated, then this will be retried.
	return "", nil
}

type dbinfo struct {
	Members []member `json:"members,omitempty"`
}
type member struct {
	Name       string   `json:"name,omitempty"`
	ClientURLs []string `json:"clientURLs,omitempty"`
}
