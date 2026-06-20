# Linux Container and Docker Security Audit

osquery queries for auditing container security posture and detecting container escape conditions: privileged containers, mounted Docker socket, host PID/network namespace sharing, containers with excessive capabilities, and container image inventory.

## ATT&CK Coverage

- T1611 — Escape to Host
- T1610 — Deploy Container
- T1613 — Container and Resource Discovery

## Queries

### Running Docker Containers

```sql
-- All running containers with key security configuration
SELECT id,
       name,
       image,
       status,
       started_at,
       pid,
       privileged,
       security_options
FROM docker_containers
WHERE status = 'running';
```

### Privileged Containers (Escape Risk)

```sql
-- Privileged containers can escape to the host trivially
SELECT id,
       name,
       image,
       status,
       pid
FROM docker_containers
WHERE privileged = 1
  AND status = 'running';
```

### Containers with Docker Socket Mounted

```sql
-- Docker socket mount gives container full control of the host
SELECT c.id,
       c.name,
       c.image,
       dm.source,
       dm.destination,
       dm.mode
FROM docker_containers c
JOIN docker_container_mounts dm ON c.id = dm.id
WHERE dm.source LIKE '%docker.sock%'
  AND c.status = 'running';
```

### Containers with Host Namespace Access

```sql
-- Host PID or network namespace = container can see/interact with host processes
SELECT c.id,
       c.name,
       c.image,
       c.pid_mode,
       c.network_mode
FROM docker_containers c
WHERE (c.pid_mode = 'host' OR c.network_mode = 'host')
  AND c.status = 'running';
```

### Container Mount Points (Host Filesystem Access)

```sql
-- What host paths are mounted into containers?
SELECT c.name,
       c.image,
       dm.source AS host_path,
       dm.destination AS container_path,
       dm.mode AS read_write
FROM docker_containers c
JOIN docker_container_mounts dm ON c.id = dm.id
WHERE dm.source LIKE '/%'
  AND dm.source NOT LIKE '/var/lib/docker/%'
  AND c.status = 'running'
ORDER BY c.name;
```

### Container Images

```sql
-- All container images with age and size
SELECT id,
       tags,
       size_bytes / 1048576 AS size_mb,
       created,
       datetime(created, 'unixepoch') AS created_time
FROM docker_images
ORDER BY created DESC;
```

### Container Processes (Cross-Boundary Visibility)

```sql
-- Processes running inside containers
SELECT p.pid,
       p.name,
       p.cmdline,
       p.uid,
       p.cgroup_path,
       dc.name AS container_name
FROM processes p
JOIN docker_containers dc ON p.cgroup_path LIKE '%' || dc.id || '%'
WHERE dc.status = 'running'
ORDER BY dc.name, p.pid;
```

## Deployment

```ini
{
  "schedule": {
    "privileged_containers": {
      "query": "SELECT id, name, image FROM docker_containers WHERE privileged = 1 AND status = 'running';",
      "interval": 300,
      "description": "Privileged containers (escape risk)"
    },
    "docker_socket_mounts": {
      "query": "SELECT c.name, c.image, dm.source FROM docker_containers c JOIN docker_container_mounts dm ON c.id = dm.id WHERE dm.source LIKE '%docker.sock%' AND c.status = 'running';",
      "interval": 300,
      "description": "Containers with Docker socket mounted"
    },
    "host_namespace_containers": {
      "query": "SELECT name, image, pid_mode, network_mode FROM docker_containers WHERE (pid_mode = 'host' OR network_mode = 'host') AND status = 'running';",
      "interval": 300,
      "description": "Containers with host namespace access"
    }
  }
}
```

## Learn More

- [Linux IR — Container Forensics](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/) — container security assessment and escape investigation
- [M365 Security Architecture — Cloud Workload Security](https://ridgelinecyber.com/training/courses/m365-security-architecture/) — container security architecture
