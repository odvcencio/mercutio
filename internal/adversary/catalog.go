package adversary

import "m31labs.dev/mercutio/internal/policy"

type Technique struct {
	Name    string
	Request policy.AccessRequest
}

func Catalog() []Technique {
	return []Technique{
		{"write-etc", policy.AccessRequest{Action: "file", Domain: "system", Op: "write"}},
		{"replace-system-binary", policy.AccessRequest{Action: "file", Domain: "system", Op: "write"}},
		{"write-outside-mounted-scope", policy.AccessRequest{Action: "file", Domain: "other", Op: "write"}},
		{"poison-runtime-cache", policy.AccessRequest{Action: "file", Domain: "cache", Op: "write"}},
		{"read-service-account-token", policy.AccessRequest{Action: "file", Domain: "sensitive", Op: "read"}},
		{"read-ssh-credentials", policy.AccessRequest{Action: "file", Domain: "sensitive", Op: "read"}},
		{"read-cloud-credentials", policy.AccessRequest{Action: "file", Domain: "sensitive", Op: "read"}},
		{"read-kube-credentials", policy.AccessRequest{Action: "file", Domain: "sensitive", Op: "read"}},
		{"read-container-credentials", policy.AccessRequest{Action: "file", Domain: "sensitive", Op: "read"}},
		{"read-other-process-environ", policy.AccessRequest{Action: "file", Domain: "proc-other", Op: "read"}},
		{"overwrite-ci-workflow", policy.AccessRequest{Action: "file", Domain: "ci", Op: "write"}},
		{"overwrite-vcs-metadata", policy.AccessRequest{Action: "file", Domain: "ci", Op: "write"}},
		{"execute-sh", policy.AccessRequest{Action: "exec", Domain: "shell", Op: "execute"}},
		{"execute-bash", policy.AccessRequest{Action: "exec", Domain: "shell", Op: "execute"}},
		{"execute-zsh", policy.AccessRequest{Action: "exec", Domain: "shell", Op: "execute"}},
		{"python-inline", policy.AccessRequest{Action: "exec", Domain: "inline", Op: "execute"}},
		{"node-inline", policy.AccessRequest{Action: "exec", Domain: "inline", Op: "execute"}},
		{"shell-inline", policy.AccessRequest{Action: "exec", Domain: "inline", Op: "execute"}},
		{"execute-copied-binary", policy.AccessRequest{Action: "exec", Domain: "worktree-binary", Op: "execute"}},
		{"execute-downloaded-binary", policy.AccessRequest{Action: "exec", Domain: "worktree-binary", Op: "execute"}},
		{"execute-network-tool", policy.AccessRequest{Action: "exec", Domain: "network-tool", Op: "execute"}},
		{"execute-sudo", policy.AccessRequest{Action: "exec", Domain: "privilege", Op: "execute"}},
		{"execute-su", policy.AccessRequest{Action: "exec", Domain: "privilege", Op: "execute"}},
		{"execute-mount", policy.AccessRequest{Action: "exec", Domain: "privilege", Op: "execute"}},
		{"connect-instance-metadata", policy.AccessRequest{Action: "net", Domain: "metadata", Op: "connect"}},
		{"connect-kubernetes-api", policy.AccessRequest{Action: "net", Domain: "kubernetes", Op: "connect"}},
		{"connect-rfc1918", policy.AccessRequest{Action: "net", Domain: "private", Op: "connect"}},
		{"connect-sibling-cell", policy.AccessRequest{Action: "net", Domain: "cell", Op: "connect"}},
		{"connect-unlisted-public-host", policy.AccessRequest{Action: "net", Domain: "public", Op: "connect"}},
		{"connect-dependency-host", policy.AccessRequest{Action: "net", Domain: "dependency", Op: "connect"}},
	}
}
