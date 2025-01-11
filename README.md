# Startup Guide

Simulation uses run.py file
Utilization on raspberry pis requires loading the image and using docker compose up
Main Branch supports both sim and live environments with terminal

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
