# Simulation Startup Guide

## Quick Start

1. **First-time startup:**
   ```
   python3 run.py --startup
   ```

2. **View all available flags (optional):**
   ```
   python3 run.py --help
   ```

3. **Configure IP address:**
   - Run `ifconfig` and locate the `inet addr`
   - Use this IP address in your configuration

## Deployment Steps

1. Build Docker image, tag, and push to DockerHub
2. Start Minikube
3. Apply Kubernetes manifests

### Docker Build and Push

```bash
docker build -t cyu72/<image-name>:latest -f <path-to-dockerfile> .
docker push cyu82/repository:tag
```

### Minikube Startup with Calico and MetalLB

1. Start Minikube with Calico:
   ```
   minikube start --network-plugin=cni --cni=calico
   ```

2. Apply Calico and MetalLB manifests:
   ```
   kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml
   kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml
   ```

3. Enable MetalLB addon:
   ```
   minikube addons enable metallb
   ```

4. Check if the cluster is ready:
   ```
   while true; do kubectl get pods -l k8s-app=calico-node -A; sleep 2; done
   ```
   Or on Linux:
   ```
   watch kubectl get pods -l k8s-app=calico-node -A
   ```

## Kubernetes Commands

| Action | Command |
|--------|---------|
| Delete all pods | `kubectl delete pods --all` |
| Check pods | `kubectl get pods` |
| Describe a pod | `kubectl describe pods [pod-name]` |
| Apply Kubernetes file | `kubectl apply -f [deployment.yaml]` |
| Connect to container | `kubectl attach <container-name>` |
| Connect interactively | `kubectl attach -it <container-name>` |

## Helpful Resources

- YAML Linter: [https://www.yamllint.com/](https://www.yamllint.com/)
- Kube by Example (MetalLB): [https://kubebyexample.com/learning-paths/metallb/install](https://kubebyexample.com/learning-paths/metallb/install)
