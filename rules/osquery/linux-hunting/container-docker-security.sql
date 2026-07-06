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

-- Privileged containers can escape to the host trivially
SELECT id,
       name,
       image,
       status,
       pid
FROM docker_containers
WHERE privileged = 1
  AND status = 'running';

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

-- Host PID or network namespace = container can see/interact with host processes
SELECT c.id,
       c.name,
       c.image,
       c.pid_mode,
       c.network_mode
FROM docker_containers c
WHERE (c.pid_mode = 'host' OR c.network_mode = 'host')
  AND c.status = 'running';

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

-- All container images with age and size
SELECT id,
       tags,
       size_bytes / 1048576 AS size_mb,
       created,
       datetime(created, 'unixepoch') AS created_time
FROM docker_images
ORDER BY created DESC;

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
