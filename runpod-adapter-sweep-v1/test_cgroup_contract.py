#!/usr/bin/env python3
"""Model-free cgroup v1/v2 admission and evidence regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import cgroup_contract as contract


MINIMUM_MEMORY_BYTES = 110 * 1024**3


class CgroupContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="corelm-cgroup-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def _write(self, path: Path, value: str) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")

    def _proc_files(self, cgroup: str, mountinfo: str) -> tuple[Path, Path]:
        cgroup_path = self.root / "proc-self-cgroup"
        mountinfo_path = self.root / "proc-self-mountinfo"
        self._write(cgroup_path, cgroup)
        self._write(mountinfo_path, mountinfo)
        return cgroup_path, mountinfo_path

    def _v2_counters(
        self,
        directory: Path,
        *,
        cpu: str = "1600000 100000",
        current: int = 1024,
        peak: int = 2048,
        limit: str = str(128 * 1024**3),
    ) -> None:
        self._write(directory / "cpu.max", cpu + "\n")
        self._write(directory / "memory.current", f"{current}\n")
        self._write(directory / "memory.peak", f"{peak}\n")
        self._write(directory / "memory.max", limit + "\n")

    def _v1_counters(
        self,
        cpu_directory: Path,
        memory_directory: Path,
        *,
        quota: str = "1600000",
        period: str = "100000",
        current: int = 1024,
        peak: int = 2048,
        limit: int = 128 * 1024**3,
    ) -> None:
        self._write(cpu_directory / "cpu.cfs_quota_us", quota + "\n")
        self._write(cpu_directory / "cpu.cfs_period_us", period + "\n")
        self._write(memory_directory / "memory.usage_in_bytes", f"{current}\n")
        self._write(memory_directory / "memory.max_usage_in_bytes", f"{peak}\n")
        self._write(memory_directory / "memory.limit_in_bytes", f"{limit}\n")

    def test_v2_private_namespace_preserves_max_semantics(self) -> None:
        mount = self.root / "cgroup2"
        self._v2_counters(mount, cpu="max 100000", limit="max")
        cgroup, mountinfo = self._proc_files(
            "0::/\n",
            f"31 25 0:30 /docker/container-id {mount} rw - cgroup2 cgroup rw\n",
        )
        observed = contract.observe(cgroup, mountinfo)
        self.assertEqual(observed.version, "v2")
        self.assertIsNone(observed.cpu_quota)
        self.assertEqual(observed.cpu_period, 100000)
        self.assertIsNone(observed.memory_limit)
        contract.admit(observed, 16, MINIMUM_MEMORY_BYTES)

    def test_v2_finite_host_relative_limits_are_admitted(self) -> None:
        mount = self.root / "cgroup2-host"
        nested = mount / "docker/container-id"
        self._v2_counters(nested)
        cgroup, mountinfo = self._proc_files(
            "0::/docker/container-id\n",
            f"31 25 0:30 / {mount} rw - cgroup2 cgroup rw\n",
        )
        observed = contract.observe(cgroup, mountinfo)
        self.assertEqual(observed.cpu_quota, 1600000)
        self.assertEqual(observed.cpu_period, 100000)
        self.assertEqual(observed.memory_limit, 128 * 1024**3)
        contract.admit(observed, 16, MINIMUM_MEMORY_BYTES)

    def test_v1_private_namespace_maps_self_root_to_each_mount(self) -> None:
        cpu_mount = self.root / "cpu-private"
        memory_mount = self.root / "memory-private"
        self._v1_counters(cpu_mount, memory_mount)
        cgroup, mountinfo = self._proc_files(
            "2:cpu,cpuacct:/\n3:memory:/\n",
            "".join(
                (
                    f"31 25 0:30 /docker/container-id {cpu_mount} rw - cgroup cgroup rw,cpu,cpuacct\n",
                    f"32 25 0:31 /docker/container-id {memory_mount} rw - cgroup cgroup rw,memory\n",
                )
            ),
        )
        observed = contract.observe(cgroup, mountinfo)
        self.assertEqual(observed.version, "v1")
        contract.admit(observed, 16, MINIMUM_MEMORY_BYTES)

    def test_v1_host_namespace_uses_self_path_not_decoy_root(self) -> None:
        cpu_mount = self.root / "cpu"
        memory_mount = self.root / "memory"
        self._v1_counters(
            cpu_mount,
            memory_mount,
            quota="100000",
            limit=1024,
        )
        self._v1_counters(
            cpu_mount / "docker/container-id",
            memory_mount / "docker/container-id",
            quota="2720000",
            period="100000",
            current=4096,
            peak=8192,
            limit=249999998976,
        )
        cgroup, mountinfo = self._proc_files(
            "2:cpu,cpuacct:/docker/container-id\n3:memory:/docker/container-id\n",
            "".join(
                (
                    f"31 25 0:30 / {cpu_mount} rw - cgroup cgroup rw,cpu,cpuacct\n",
                    f"32 25 0:31 / {memory_mount} rw - cgroup cgroup rw,memory\n",
                )
            ),
        )
        observed = contract.observe(cgroup, mountinfo)
        self.assertEqual(observed.version, "v1")
        self.assertEqual(observed.cpu_quota, 2720000)
        self.assertEqual(observed.memory_current, 4096)
        self.assertEqual(observed.memory_peak, 8192)
        self.assertEqual(observed.memory_limit, 249999998976)
        contract.admit(observed, 16, MINIMUM_MEMORY_BYTES)

    def test_v1_subtree_mount_and_huge_unlimited_style_limit_are_admitted(self) -> None:
        cpu_mount = self.root / "cpu-subtree"
        memory_mount = self.root / "memory-subtree"
        huge_limit = 9223372036854771712
        self._v1_counters(
            cpu_mount,
            memory_mount,
            quota="-1",
            limit=huge_limit,
        )
        cgroup, mountinfo = self._proc_files(
            "2:cpu,cpuacct:/docker/container-id\n3:memory:/docker/container-id\n",
            "".join(
                (
                    f"31 25 0:30 /docker/container-id {cpu_mount} rw - cgroup cgroup rw,cpu,cpuacct\n",
                    f"32 25 0:31 /docker/container-id {memory_mount} rw - cgroup cgroup rw,memory\n",
                )
            ),
        )
        observed = contract.observe(cgroup, mountinfo)
        self.assertIsNone(observed.cpu_quota)
        self.assertEqual(observed.memory_limit, huge_limit)
        contract.admit(observed, 16, MINIMUM_MEMORY_BYTES)

    def test_invalid_v1_quotas_and_low_finite_limits_fail_closed(self) -> None:
        for quota in ("-2", "0", "invalid"):
            with self.subTest(quota=quota):
                cpu_mount = self.root / f"cpu-{quota}"
                memory_mount = self.root / f"memory-{quota}"
                self._v1_counters(cpu_mount, memory_mount, quota=quota)
                cgroup, mountinfo = self._proc_files(
                    "2:cpu,cpuacct:/\n3:memory:/\n",
                    "".join(
                        (
                            f"31 25 0:30 / {cpu_mount} rw - cgroup cgroup rw,cpu,cpuacct\n",
                            f"32 25 0:31 / {memory_mount} rw - cgroup cgroup rw,memory\n",
                        )
                    ),
                )
                with self.assertRaises(contract.CgroupContractError):
                    contract.observe(cgroup, mountinfo)

        cpu_mount = self.root / "cpu-low"
        memory_mount = self.root / "memory-low"
        self._v1_counters(
            cpu_mount,
            memory_mount,
            quota="1599999",
            limit=MINIMUM_MEMORY_BYTES - 1,
        )
        cgroup, mountinfo = self._proc_files(
            "2:cpu,cpuacct:/\n3:memory:/\n",
            "".join(
                (
                    f"31 25 0:30 / {cpu_mount} rw - cgroup cgroup rw,cpu,cpuacct\n",
                    f"32 25 0:31 / {memory_mount} rw - cgroup cgroup rw,memory\n",
                )
            ),
        )
        observed = contract.observe(cgroup, mountinfo)
        with self.assertRaises(contract.CgroupContractError):
            contract.admit(observed, 16, MINIMUM_MEMORY_BYTES)
        self._write(cpu_mount / "cpu.cfs_quota_us", "1600000\n")
        memory_only_low = contract.observe(cgroup, mountinfo)
        with self.assertRaises(contract.CgroupContractError):
            contract.admit(memory_only_low, 16, MINIMUM_MEMORY_BYTES)

    def test_missing_duplicate_symlink_and_inverted_peak_are_rejected(self) -> None:
        cgroup, mountinfo = self._proc_files("0::/\n", "1 1 0:1 / / rw - tmpfs tmpfs rw\n")
        with self.assertRaises(contract.CgroupContractError):
            contract.observe(cgroup, mountinfo)

        mount = self.root / "ambiguous-v2"
        self._v2_counters(mount, current=4096, peak=2048)
        cgroup, mountinfo = self._proc_files(
            "0::/\n",
            f"31 25 0:30 / {mount} rw - cgroup2 cgroup rw\n",
        )
        with self.assertRaises(contract.CgroupContractError):
            contract.observe(cgroup, mountinfo)

        second = self.root / "second-v2"
        self._v2_counters(mount, current=1024, peak=2048)
        self._v2_counters(second)
        self._write(
            mountinfo,
            "".join(
                (
                    f"31 25 0:30 / {mount} rw - cgroup2 cgroup rw\n",
                    f"32 25 0:31 / {second} rw - cgroup2 cgroup rw\n",
                )
            ),
        )
        with self.assertRaises(contract.CgroupContractError):
            contract.observe(cgroup, mountinfo)

        symlink_mount = self.root / "symlink-v2"
        self._v2_counters(symlink_mount)
        (symlink_mount / "memory.max").unlink()
        (symlink_mount / "memory.max").symlink_to(symlink_mount / "memory.peak")
        self._write(
            mountinfo,
            f"33 25 0:32 / {symlink_mount} rw - cgroup2 cgroup rw\n",
        )
        with self.assertRaises(contract.CgroupContractError):
            contract.observe(cgroup, mountinfo)


if __name__ == "__main__":
    unittest.main()
