# FFSFS Multi-Backend Storage Design & Architecture

This document outlines the design for allowing a single FUSE service instance to manage multiple physical storage locations (backends) under a single mountpoint, while gracefully handling swappable/offline external drives and managing independent realms.

---

## 1) Realms: Separate Services vs. Single Service

**Decision:** **Keep realms as separate service instances (independent FUSE mounts), but allow a single realm to span multiple disks.**

### Rationale:
- **Logical & Security Isolation:** Realms are intended as independent namespaces with distinct metadata logs, peers, encryption keys, and access controls. Mixing them under a single FUSE mount makes permission mapping, security boundaries, and path isolation much harder.
- **Deployment Flexibility:** Users can choose which realms to mount on which machines (e.g., a laptop mounts `personal` but not `work-secrets`).
- **Simplicity:** A FUSE daemon per realm keeps the virtual filesystem implementation clean and focused on a single namespace. 

---

## 2) Multi-Backend Storage Pool (The "Union/Tiered" Model)

Within a single realm's service instance, we can configure a tiered storage pool consisting of multiple physical storage locations (backends).

```mermaid
graph TD
    subgraph FUSE Mount
        MP["~/my-realm/ (Mountpoint)"]
    end
    
    subgraph FFSFS Frontend Service
        FS["FFSFS Operations Manager"]
        Meta["Metadata Log Manager (SSD)"]
    end

    subgraph Storage Pool (Backends)
        SSD["/home/user/.my-realm/ (Internal SSD - Primary & Metadata)"]
        HDD1["/media/ext-hdd-1/.ffsfs_data/ (External HDD 1 - Large Store)"]
        HDD2["/media/ext-hdd-2/.ffsfs_data/ (External HDD 2 - Swappable Backup)"]
    end

    MP --> FS
    FS --> Meta
    FS --> SSD
    FS -.->|Fallback / Sync| HDD1
    FS -.->|Fallback / Sync| HDD2
```

### Proposed Tiered Architecture:
1. **Primary/Metadata Backend (Always-Online - SSD):**
   - **Role:** Fast cache, write buffer, and authoritative metadata host.
   - **Contents:** 
     - Authoritative metadata logs (`.ffsfs-meta.log`).
     - In-flight temporary files (`.NULL_HASH.`).
     - Hot-cache of recently read/written file payloads.
   - **Benefit:** Direct operations like `readdir`, `getattr`, and creating new files remain extremely fast because they only touch the local SSD.
2. **Secondary/Data Backends (Large/Swappable - HDDs):**
   - **Role:** Permanent storage for large committed file payloads.
   - **Contents:** Actual versioned files (`file.txt.HASH.write.0.TS`).
   - **Benefit:** Large video, music, or photo assets live on high-capacity spinning disks, keeping the primary SSD clean.

---

## 3) Handling Unmounted and Swapped Disks (Offline Tolerance)

To make the system robust against external drives being unplugged, swapped, or failing to mount, we introduce **decoupled metadata** and **dynamic volume tracking**.

### Key Mechanisms:

### A. Decoupled Metadata & Virtual Attributes
Because the metadata log (`.ffsfs-meta.log`) remains online on the SSD, FUSE can list files and return file sizes (`getattr`) even if the drive holding the payload is unplugged.
- If a user reads a file whose payload is only on an **offline** disk:
  - FUSE returns a descriptive error like `ENODEV` (No such device) or `EHOSTUNREACH` (Host is unreachable).
  - Alternatively, if peers are online, FUSE can fetch the payload from a peer over the network, effectively bypassing the offline local disk.

### B. Volume Identifiers (`.ffsfs-volume.id`)
Each configured backend directory is assigned a unique volume ID stored in a small JSON file (e.g., `.ffsfs-volume.id`) at the root of that drive's backend folder.
- On startup and before I/O, FFSFS reads the volume ID.
- If the file is missing or the directory is unreadable, the backend is marked as **OFFLINE**.
- The frontend dynamically routes write/read requests to the remaining **ONLINE** backends.

### C. Write-Anywhere & Background Catch-Up
- **Writing:** When a file is committed, if the configured target HDD is offline, the FUSE daemon commits the file to the local SSD cache (or any other online HDD).
- **Background Replication:** A background worker monitors drive mounts. When it detects a previously offline HDD has reconnected, it scans the metadata log and replicates any new files that were committed in the interim.
- **Disk Rotation (Rolling Backups):** If you swap HDD1 for HDD2, the sync worker automatically identifies HDD2, sees it is missing the latest writes, and syncs them to it, ensuring that both rotating backup drives are kept up to date when plugged in.

---

## 4) Configuration & User Configuration Tool (ffsctl / Configuration Space)

We need a simple tool or subcommand to set up, remove, and query the status of backends in the storage pool. This will be integrated into the existing `ffsctl.py` CLI or built as a dedicated configuration utility.

### Configuration Schema (`.storage/realm-config.json`):
```json
{
  "realm": "my-realm",
  "storage_pool": {
    "primary": {
      "path": "/home/user/.my-realm",
      "type": "ssd",
      "cache_limit_gb": 50
    },
    "backends": [
      {
        "id": "vol-external-hdd-1",
        "path": "/media/user/backup-hd-1/ffsfs_data",
        "role": "archive",
        "mirror": true,
        "media": "hdd",
        "max_bytes": null,
        "max_file_size": null,
        "reserve_bytes": null
      }
    ]
  }
}
```

### Proposed CLI Subcommands under `ffsctl`:
1. **Initialize a Storage Space (Backend):**
   ```bash
   python3 ffsctl.py backend add <realm> <path> [--id <name>] [--role <role>] [--mirror]
   ```
   - Checks if the target path is a valid directory.
   - Generates and writes `.ffsfs-volume.id` containing a unique ID.
   - Appends the backend definition to the realm configuration.
   - `--mirror` enables mirror-on-write plus pending catch-up retry for that
     backend. Media/capacity hints can be stored for future routing policy.

2. **Remove a Storage Space:**
   ```bash
   python3 ffsctl.py backend remove <realm> <id_or_path>
   ```
   - Removes the backend entry from the configuration. (Does not delete files on the disk, just detaches it from the realm storage pool).

3. **List Storage Space Status:**
   ```bash
   python3 ffsctl.py backend list <realm>
   ```
   - Lists all configured backends, their paths, configured roles, and current status (`ONLINE` / `OFFLINE` based on `.ffsfs-volume.id` check).

4. **Verify/Rebuild Volume ID:**
   ```bash
   python3 ffsctl.py backend register <realm> <path>
   ```
   - Registers an existing backup disk that already has a `.ffsfs-volume.id` on it, re-linking it to this host's configuration space.
