# KinD OIDC

This repo contains a small example that demonstrates how to set up a KinD
cluster with support for Service Account Projected Volumes.

Service Account Projected Volumes are useful because they let pods project
an `aud` (audience) scoped, time-limited OIDC token into the container.  These
short-lived, scoped tokens may be used to identify the workload against
external systems (assuming the issuer/discovery URL are accessible, as they are
on at least GKE and EKS clusters).

The goal of this repo is to demonstrate how KinD may be used to configure a
KinD cluster as a suitable e2e test environment for applications that want
to send/receive this form of token.

## Key Elements

When spinning up the KinD cluster, apply the following patch to enable support
for the projected volumes, and to make the OIDC token's `iss` field use
`https://kubernetes.default.svc` (so it is accessible on-cluster):
```yaml
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta2
  kind: ClusterConfiguration
  metadata:
    name: config
  apiServer:
  extraArgs:
    "service-account-issuer": "https://kubernetes.default.svc"
    "service-account-signing-key-file": "/etc/kubernetes/pki/sa.key"
    "service-account-jwks-uri": "https://kubernetes.default.svc/openid/v1/jwks"
    "service-account-key-file": "/etc/kubernetes/pki/sa.pub"
```

By default, the discovery endpoint on the KinD cluster is locked down, but the
discovery endpoint can be opened up with the following command:

```shell
kubectl create clusterrolebinding oidc-reviewer \
  --clusterrole=system:service-account-issuer-discovery \
  --group=system:unauthenticated
```

The above is from a [great article](https://banzaicloud.com/blog/kubernetes-oidc/)
which says:
> To be able to fetch the public keys and validate the JWT tokens against
> the Kubernetes cluster’s issuer we have to allow external unauthenticated
> requests. To do this, we bind this special role with a ClusterRoleBinding
> to unauthenticated users (make sure that this is safe in your environment,
> but only public keys are visible on this URL)


The final bit you need (for KinD) is to ensure you trust the Cluster's CA
in your OIDC verification logic because the issuer endpoint's TLS is not
signed by a public CA on KinD clusters.  This can be done with the Go
snippet:

```go
	const k8sCA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// Add the Kubernetes cluster's CA to the system CA pool, and to
	// the default transport.
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	certs, err := os.ReadFile(k8sCA)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", k8sCA, err)
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("No certs appended, using system certs only")
	}

    // WARNING: This changes the program's default transport.  If this
    // is undesirable, or your OIDC verification library supports passing
    // an HTTP transport, then favor passing `t` over setting
    // `http.DefaultTransport`
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig.RootCAs = rootCAs
	http.DefaultTransport = t
```

