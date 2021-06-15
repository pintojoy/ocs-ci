import logging
import base64
import time
import os

from ocs_ci.ocs.resources.pod import (
    get_mon_pods,
    get_osd_pods,
)
from ocs_ci.ocs.resources import pod

from ocs_ci.ocs import ocp, constants
from ocs_ci.utility.utils import run_cmd
from ocs_ci.ocs.ocp import OCP

from ocs_ci.helpers.helpers import wait_for_resource_state

logger = logging.getLogger(__name__)


class TestMOnCorruptRecovery:
    def test_mon_corrupt(self):
        corrupt_mons()

        take_backup()

        patch_osds()

        patch_mon()

        mon_rebuild()

        revert_patches()


def get_secrets(secret_resource):
    keyring = ""
    for resource in secret_resource:
        resource_obj = ocp.OCP(
            resource_name=resource, kind="Secret", namespace="openshift-storage"
        )
        keyring = (
            keyring
            + base64.b64decode(resource_obj.get().get("data").get("keyring"))
            .decode()
            .rstrip("\n")
            + "\n"
        )
    return keyring


def corrupt_mons():
    mon_pods = get_mon_pods()
    for mon in mon_pods:
        logger.info(f"Corrupting mon {mon.name}")
        mon_id = mon.get().get("metadata").get("labels").get("ceph_daemon_id")
        logger.info(
            mon.exec_cmd_on_pod(
                command=f"rm -rf  /var/lib/ceph/mon/ceph-{mon_id}/store.db"
            )
        )

    for mon in get_mon_pods():
        wait_for_resource_state(mon, state=constants.STATUS_CLBO)


def take_backup():
    logger.info("Starting recovery procedure")
    ocp = OCP(kind="Deployment", namespace=constants.OPENSHIFT_STORAGE_NAMESPACE)
    logger.info("scaling down rook-ceph-operator ")
    ocp.exec_oc_cmd(f"scale deployment rook-ceph-operator --replicas=0")
    logger.info("scaling down ocs-operator ")
    ocp.exec_oc_cmd(f"scale deployment ocs-operator --replicas=0")
    backup_cmd = """
mkdir /tmp/backup
for d in $(oc get deployment|awk -F' ' '{print $1}'|grep -v NAME); 
do
echo $d;oc get deployment $d -o yaml > /tmp/backup/oc_get_deployment.${d}.yaml; 
done
    """
    logger.info("Taking backup of deployments")
    run_cmd(backup_cmd)


def patch_osds():
    logger.info("getting osd pods")
    for osd in get_osd_pods():
        logger.info("pathcing osd with livenessProbe and sleep infinity command")
        params = (
            '[{"op":"remove", "path":"/spec/template/spec/containers/0/livenessProbe"}]'
        )
        logger.info(
            ocp.OCP().patch(
                resource_name=osd.name,
                params=params.strip,
                format_type="json",
            )
        )

        params = '{"spec": {"template": {"spec": {"containers": [{"name": "osd", "command": ["sleep", "infinity"], "args": []}]}}}}'
        logger.info(
            ocp.OCP().patch(
                resource_name=osd.name,
                params=params.strip("\n"),
                format_type="json",
            )
        )
    logger.info("sleeping, waiting for osds to reach Running")
    time.sleep(30)
    for osd in get_osd_pods():
        wait_for_resource_state(osd, state=constants.STATUS_RUNNING)


def get_monstore():
    logger.info("Taking COT data from Each OSDs")
    recover_mon = """
    #!/bin/bash -x
    ms=/tmp/monstore

    rm -rf $ms
    mkdir $ms

    for osd_pod in $(oc get po -l app=rook-ceph-osd -oname -n openshift-storage); do

      echo "Starting with pod: $osd_pod"

      oc rsync $ms $osd_pod:$ms

      rm -rf $ms
      mkdir $ms

      echo "pod in loop: $osd_pod ; done deleting local dirs"

      oc exec $osd_pod -- mkdir $ms
      oc exec $osd_pod -- ceph-objectstore-tool --type bluestore --data-path /var/lib/ceph/osd/ceph-$(oc get $osd_pod -ojsonpath='{ .metadata.labels.ceph_daemon_id }') --op update-mon-db --no-mon-config --mon-store-path $ms

      echo "Done with COT on pod: $osd_pod"

      oc rsync $osd_pod:$ms $ms

      echo "Finished pulling COT data from pod: $osd_pod"

    done
    """
    with open("/tmp/backup/recover_mon.sh", "w") as file:
        file.write(recover_mon)
    os.system(command="chmod +x /tmp/backup/recover_mon.sh")
    logger.info("Getting monstore..")
    os.system(command="sh backup/recover_mon.sh")
    os.system(command="rm -rf  backup/recover_mon.sh")


def patch_mon():
    for mon in get_mon_pods():
        params = '{"spec": {"template": {"spec": {"containers": [{"name": "mon", "command": ["sleep", "infinity"], "args": []}]}}}}'
        logger.info(f"patching mon {mon} for sleep")
        logger.info(
            ocp.OCP(kind="Deployment", namespace="openshift-storage").patch(
                resource_name=mon,
                params=params.strip("\n"),
            )
        )

    logger.info("Updating initialDelaySeconds in mon-a deployment")
    mon_a_sleep = """ oc get deployment   rook-ceph-mon-a   -o yaml | sed "s/initialDelaySeconds: 10/initialDelaySeconds: 2000/g" | oc replace -f - """
    run_cmd(mon_a_sleep)


def mon_rebuild():
    mon_a = get_mon_pods()[0]

    logger.info("Working on mon a")
    logger.info(mon_a.name)
    cmd = f"oc cp /tmp/monstore/ {mon_a.name}:/tmp/"
    logger.info(f"copying monstore into mon {mon_a.name}")
    logger.info(run_cmd(cmd=cmd))

    logger.info("running chown")
    logger.info(mon_a.exec_cmd_on_pod(command="chown -R ceph:ceph /tmp/monstore"))

    logger.info("Generating monmap creation command..")
    logger.info("getting mon pods public ip")
    #
    cm = ocp.OCP(
        resource_name=constants.ROOK_CEPH_MON_ENDPOINTS,
        kind="configmap",
        namespace="openshift-storage",
    )
    mon_ips = re.findall(r"[0-9]+(?:\.[0-9]+){3}", cm.get().get("data").get("data"))
    mon_ips_dict = {}
    mon_pods = get_mon_pods()
    mon_ids = []
    for mon in mon_pods:
        mon_ids.append(mon.get().get("metadata").get("labels").get("ceph_daemon_id"))

    fsid = (
        mon_pods[0]
        .get()
        .get("spec")
        .get("containers")[0]
        .get("args")[0]
        .replace("--fsid=", "")
    )

    for id, ip in zip(mon_ids, mon_ips):
        ipv1 = ipv2 = ip
        ipv1 = "v1:" + ipv1 + ":6789"
        ipv2 = "v2:" + ipv2 + ":3300"
        mon_ips_dict.update({id: f"[{ipv2},{ipv1}]"})

    mon_ip_ids = ""
    for key, val in mon_ips_dict.items():
        mon_ip_ids = mon_ip_ids + f"--addv {key} {val}" + " "

    mon_map_cmd = (
        f"monmaptool --create {mon_ip_ids} --enable-all-features --clobber /tmp/monmap "
        f"--fsid {fsid}"
    )

    logger.info("Creating monmap")
    logger.info(mon_map_cmd)
    mon_a.exec_cmd_on_pod(command=mon_map_cmd)

    logger.info("getting secrets")

    secret_resources = {
        "mons": {"rook-ceph-mons-keyring"},
        "osds": {
            "rook-ceph-osd-0-keyring",
            "rook-ceph-osd-1-keyring",
            " rook-ceph-osd-2-keyring",
        },
        "rgws": {
            "rook-ceph-rgw-ocs-storagecluster-cephobjectstore-a-keyring",
            "rook-ceph-rgw-ocs-storagecluster-cephobjectstore-b-keyring",
        },
        "mgrs": {"rook-ceph-mgr-a-keyring"},
        "mdss": {
            "rook-ceph-mds-ocs-storagecluster-cephfilesystem-a-keyring",
            "rook-ceph-mds-ocs-storagecluster-cephfilesystem-b-keyring",
        },
    }
    mon_k = get_secrets(secret_resource=secret_resources.get("mons"))
    osd_k = get_secrets(secret_resource=secret_resources.get("osds"))
    rgw_k = get_secrets(secret_resource=secret_resources.get("rgws"))
    mgr_k = get_secrets(secret_resource=secret_resources.get("mgrs"))
    mds_k = get_secrets(secret_resource=secret_resources.get("mdss"))
    logger.info(mon_k + osd_k + rgw_k + mgr_k + mds_k)
    with open("/tmp/keyring", "w") as fd:
        fd.write(mon_k + osd_k + rgw_k + mgr_k + mds_k)
    cmd = f"oc cp /tmp/keyring {mon_a.name}:/tmp/"
    logger.info(f"copying keyring into mon {mon_a.name}")

    logger.info(run_cmd(cmd=cmd))
    rebuild_mon = "ceph-monstore-tool /tmp/monstore rebuild -- --keyring /tmp/keyring --monmap /tmp/monmap"
    logger.info("Rebuidling mon:")
    mon_a.exec_cmd_on_pod(command=rebuild_mon)

    logger.info("running chown")
    logger.info(mon_a.exec_cmd_on_pod(command="chown -R ceph:ceph /tmp/monstore"))
    logger.info("Copying rebuilt Db into mon")
    mon_a.exec_cmd_on_pod(
        command=f"mv /tmp/monstore/store.db /var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db"
    )

    cmd = f"oc cp {mon_a.name}:/var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db /tmp/store.db"
    logger.info("copying store.db dir into local")
    logger.info(run_cmd(cmd=cmd))


def rebuilding_other_mons():
    mon_b_sleep = """ oc get deployment    rook-ceph-mon-b   -o yaml | sed "s/initialDelaySeconds: 10/initialDelaySeconds: 2000/g" | oc replace -f - """
    run_cmd(mon_b_sleep)
    mon_c_sleep = """ oc get deployment    rook-ceph-mon-b  -o yaml | sed "s/initialDelaySeconds: 10/initialDelaySeconds: 2000/g" | oc replace -f - """
    run_cmd(mon_c_sleep)

    logger.info("copying store.db in other mons")
    for mon in get_mon_pods()[1:]:
        cmd = f"oc cp /tmp/store.db {mon.name}:/var/lib/ceph/mon/ceph-{mon.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db "
        logger.info(f"copying store.db to  {mon.name} ")
        logger.info(run_cmd(cmd=cmd))


def revert_patches():
    logger.info("Reverting patches deployments")
    revert_patch = "oc replace --force -f /tmp/backup/"
    run_cmd(revert_patch)
    logger.info("sleeping., waiting for all pods up and running..")
    time.sleep(60)
    assert pod.wait_for_pods_to_be_running(timeout=300)

    ocp = OCP(kind="Deployment", namespace=constants.OPENSHIFT_STORAGE_NAMESPACE)
    logger.info("scaling up rook-ceph-operator ")
    ocp.exec_oc_cmd(f"scale deployment rook-ceph-operator --replicas=1")
    logger.info("scaling up ocs-operator ")
    ocp.exec_oc_cmd(f"scale deployment ocs-operator --replicas=1")

    time.sleep(60)