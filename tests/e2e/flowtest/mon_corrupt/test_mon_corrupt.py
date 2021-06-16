import logging

from ocs_ci.ocs.resources.pod import (
    get_pod_node,
    get_mon_pods,
    get_ceph_tools_pod,
    get_mgr_pods,
    get_osd_pods,
)


logger = logging.getLogger(__name__)

class TestMOnCorrupt():
    def test_mon_corrupt(self):
        mon_pods = get_mon_pods()
        for mon in mon_pods:
            mon_id = mon.get().get('metadata').get('labels').get('ceph_daemon_id')
            logger.info(mon.exec_cmd_on_pod(command=f'rm -rf  /var/lib/ceph/mon/ceph-{mon_id}/store.db'))

