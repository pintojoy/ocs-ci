import logging
import base64
import time
import os
from os.path import join
from ocs_ci.utility import templating
import tempfile
import re

from ocs_ci.ocs.resources.pod import (
    get_mon_pods,
    get_osd_pods,
)
from ocs_ci.ocs.resources import pod

from ocs_ci.ocs import ocp, constants
from ocs_ci.ocs.ocp import OCP

from ocs_ci.helpers.helpers import wait_for_resource_state
from ocs_ci.ocs.resources.ocs import OCS

logger = logging.getLogger(__name__)


class TestMOnCorruptRecovery:
    def test_mon_corrupt(self):
        corrupt_mons() #--> working
        scale_up_down(0)# --> working
        backupdir = take_backup() #-->working
        patch_osds() #--> working
        get_monstore() #--> working
        patch_mon() #--> working
        mon_rebuild()#--> working
        rebuilding_other_mons()# --> working
        revert_patches(backupdir) #--> working
        scale_up_down(1) #--> working
        teardown()

def get_secrets(secret_resource):
    keyring = ""

    osd_caps = """
        caps mgr = "allow profile osd"
        caps mon = "allow profile osd"
        caps osd = "allow *"
"""
    for resource in secret_resource:
        resource_obj = ocp.OCP(
            resource_name=resource, kind="Secret", namespace="openshift-storage"
        )
        keyring = (
            keyring
            + base64.b64decode(resource_obj.get().get("data").get("keyring"))
            .decode().
            rstrip('\n')
            + "\n"
        )
        if 'osd' in resource:
            keyring = keyring + osd_caps
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


def scale_up_down(replaica):
    logger.info("Starting recovery procedure")
    ocp = OCP(kind="Deployment", namespace=constants.OPENSHIFT_STORAGE_NAMESPACE)
    logger.info(f"scaling rook-ceph-operator to replica {replaica}")
    ocp.exec_oc_cmd(f"scale deployment rook-ceph-operator --replicas={replaica}")
    logger.info(f"scaling down ocs-operator to replica {replaica} ")
    ocp.exec_oc_cmd(f"scale deployment ocs-operator --replicas={replaica}")


def patch_osds():
    logger.info("getting osd deployemnts")

    osd_deployments = get_deployents_objects(selector=constants.OSD_APP_LABEL)
    for osd in osd_deployments:
        logger.info("pathcing osd with livenessProbe and sleep infinity command")
        params = (
            '[{"op":"remove", "path":"/spec/template/spec/containers/0/livenessProbe"}]'
        )
        logger.info(
            ocp.OCP(kind="Deployment", namespace="openshift-storage").patch(
                resource_name=osd.name,
                params=params,
                format_type="json",

            )
        )

        params = '{"spec": {"template": {"spec": {"containers": [{"name": "osd", "command": ["sleep", "infinity"], "args": []}]}}}}'
        logger.info(
            ocp.OCP(kind="Deployment", namespace="openshift-storage").patch(
                resource_name=osd.name,
                params=params,
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
    with open("recover_mon.sh", "w") as file:
        file.write(recover_mon)
    os.system(command="chmod +x recover_mon.sh")
    logger.info("Getting monstore..")
    logger.info(os.system(command="sh recover_mon.sh"))



def patch_mon():
    mon_deployments = get_deployents_objects(selector=constants.MON_APP_LABEL)

    for mon in mon_deployments:
        params = '{"spec": {"template": {"spec": {"containers": [{"name": "mon", "command": ["sleep", "infinity"], "args": []}]}}}}'
        logger.info(f"patching mon {mon.name} for sleep")
        logger.info(
            ocp.OCP(kind="Deployment", namespace="openshift-storage").patch(
                resource_name=mon.name,
                params=params,
            )
        )

    logger.info("Updating initialDelaySeconds in mon-a deployment")
    mons_dep = get_deployents_objects(selector=constants.MON_APP_LABEL)

    insert_delay(mons_dep[0].name)
    logger.info("sleeping, waiting for mon to reach Running")
    time.sleep(30)
    wait_for_resource_state(get_mon_pods()[0], state=constants.STATUS_RUNNING)


def mon_rebuild():
    mon_a = get_mon_pods()[0]

    logger.info("Working on mon a")
    logger.info(mon_a.name)
    cmd = f"oc cp /tmp/monstore/monstore {mon_a.name}:/tmp/"
    logger.info(f"copying monstore into mon {mon_a.name}")
    logger.info(os.system(cmd))

    logger.info("running chown")
    logger.info(mon_a.exec_cmd_on_pod(command="chown -R ceph:ceph /tmp/monstore"))

    mon_map_cmd = generate_monmap()

    logger.info("Creating monmap")
    logger.info(mon_map_cmd)
    mon_a.exec_cmd_on_pod(command=mon_map_cmd)

    logger.info("getting secrets")

    keyrings_files = get_keyrings()

    for k_file in keyrings_files:
        cmd = f"oc cp {k_file} {mon_a.name}:/tmp/"
        logger.info(f"copying keyring into mon {mon_a.name}")
        logger.info(os.system(cmd))

    logger.info('Importing keyring')
    mon_a.exec_cmd_on_pod(command='cp /etc/ceph/keyring-store/keyring /tmp/keyring')
    for k_file in keyrings_files:
        logger.info(f'Importing keyring {k_file}')
        logger.info(mon_a.exec_cmd_on_pod(command=f'ceph-authtool  /tmp/keyring  --import-keyring {k_file}'))

    rebuild_mon = "ceph-monstore-tool /tmp/monstore rebuild -- --keyring /tmp/keyring --monmap /tmp/monmap"
    logger.info("Rebuidling mon:")
    mon_a.exec_cmd_on_pod(command=rebuild_mon,out_yaml_format=False)

    logger.info("running chown")
    logger.info(mon_a.exec_cmd_on_pod(command="chown -R ceph:ceph /tmp/monstore"))
    logger.info('Getting backup of store.db')
    try:
        mon_a.exec_cmd_on_pod(
            command=f"mv /var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db /var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db.crr " )
    except Exception:
        pass
    logger.info("Copying rebuilt Db into mon")
    mon_a.exec_cmd_on_pod(
        command=f"mv /tmp/monstore/store.db /var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/"
    )
    logger.info("running chown")

    mon_a.exec_cmd_on_pod(command=f"chown -R ceph:ceph /var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db")

    cmd = f"oc cp {mon_a.name}:/var/lib/ceph/mon/ceph-{mon_a.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db /tmp/store.db"
    logger.info("copying store.db dir into local")
    logger.info(cmd)
    logger.info(os.system(cmd))


def rebuilding_other_mons():
    mons_dep = get_deployents_objects(selector=constants.MON_APP_LABEL)
    insert_delay(mons_dep[1].name)
    insert_delay(mons_dep[2].name)
    logger.info("sleeping, waiting for mons to reach Running")
    time.sleep(90)
    for po in get_mon_pods()[1:]:
        wait_for_resource_state(po, state=constants.STATUS_RUNNING)

    logger.info("copying store.db in other mons")
    for mon in get_mon_pods()[1:]:
        try:
            mon.exec_cmd_on_pod(
                command=f"mv /var/lib/ceph/mon/ceph-{mon.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db /var/lib/ceph/mon/ceph-{mon.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db.crr ")
        except Exception:
            pass
        cmd = f"oc cp /tmp/store.db {mon.name}:/var/lib/ceph/mon/ceph-{mon.get().get('metadata').get('labels').get('ceph_daemon_id')}/ "
        logger.info(f"copying store.db to  {mon.name} ")
        logger.info(os.system(cmd))
        mon.exec_cmd_on_pod(command=f"chown -R ceph:ceph /var/lib/ceph/mon/ceph-{mon.get().get('metadata').get('labels').get('ceph_daemon_id')}/store.db")


def insert_delay(deployment):
    logger.info(f'Updating initialDelaySeconds on deployment {deployment}')
    cmd= f""" oc get deployment {deployment}  -o yaml | sed "s/initialDelaySeconds: 10/initialDelaySeconds: 2000/g" | oc replace -f - """
    logger.info(f'executing {cmd}')
    logger.info(os.system(cmd))


def revert_patches(backup_dir):
    logger.info("Reverting patches on osds and mons ")
    for dep in backup_dir:
        revert_patch = f"oc replace --force -f {dep}"
        logger.info(os.system(revert_patch))
    logger.info("sleeping., waiting for all pods up and running..")
    time.sleep(120)
    assert pod.wait_for_pods_to_be_running(timeout=300)

def take_backup():
    ocp = OCP(kind="Deployment", namespace=constants.OPENSHIFT_STORAGE_NAMESPACE)
    deployments = ocp.get("-o name", out_yaml_format=False)
    deployments_full_name = str(deployments).split()
    deployment_names = list()
    for name in deployments_full_name:
        deployment_names.append(name.lstrip("deployment.apps").lstrip("/"))

    tmp_backup_dir = tempfile.mkdtemp(prefix="backup")
    for deployment in deployment_names:
        ocp = OCP(resource_name=deployment, kind="Deployment", namespace=constants.OPENSHIFT_STORAGE_NAMESPACE)
        deployment_get = ocp.get()
        deployment_yaml = join(tmp_backup_dir, deployment+'.yaml')
        templating.dump_data_to_temp_yaml(deployment_get, deployment_yaml)

    to_revert_patches = get_deployents_objects(selector=constants.OSD_APP_LABEL) + get_deployents_objects(selector=constants.MON_APP_LABEL)
    to_revert_patches_path = []
    for dep in to_revert_patches:
        to_revert_patches_path.append(join(tmp_backup_dir, dep.name+'.yaml'))

    for pat in to_revert_patches_path:
        logger.info(pat)
    return to_revert_patches_path


def get_deployents_objects(selector):
    ocp = OCP(kind="Deployment", namespace=constants.OPENSHIFT_STORAGE_NAMESPACE)
    deployments = ocp.get(selector=selector).get("items")
    return  [OCS(**deployment) for deployment in deployments]


def teardown():
    os.system(command="rm -rf recover_mon.sh")
    os.system(command="rm -rf /tmp/monstore")
    os.system(command="rm -rf /tmp/*.keyring")
    os.system(command="rm -rf /tmp/store.db")


def get_keyrings():
    secret_resources = {
        "mons": {"rook-ceph-mons-keyring"},
        "osds": {
            "rook-ceph-osd-0-keyring",
            "rook-ceph-osd-1-keyring",
            "rook-ceph-osd-2-keyring",
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
    rgw_k = get_secrets(secret_resource=secret_resources.get("rgws"))
    mgr_k = get_secrets(secret_resource=secret_resources.get("mgrs"))
    mds_k = get_secrets(secret_resource=secret_resources.get("mdss"))
    osd_k = get_secrets(secret_resource=secret_resources.get("osds"))

    keyrings = {
        'mons': mon_k,
        'rgws': rgw_k,
        'mgrs': mgr_k,
        'mdss': mds_k,
        'osds': osd_k,
    }
    keyrings_files = []

    for k, v in keyrings.items():
        with open(f"/tmp/{k}.keyring", "w") as fd:
            fd.write(v)
            keyrings_files.append(f"/tmp/{k}.keyring")

    return keyrings_files

def generate_monmap():
    mon_a = get_mon_pods()[0]

    logger.info("Working on mon a")
    logger.info(mon_a.name)
    logger.info("Generating monmap creation command..")
    logger.info("getting mon pods public ip")

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
        logger.info(mon_ids)

    logger.info('getting fsid..')
    fsid = mon_a.get().get("spec").get("initContainers")[1].get('args')[0].replace("--fsid=", "")

    for id, ip in zip(mon_ids, mon_ips):
        ipv1 = ipv2 = ip
        ipv1 = "v1:" + ipv1 + ":6789"
        ipv2 = "v2:" + ipv2 + ":3300"
        mon_ips_dict.update({id: f"[{ipv2},{ipv1}]"})

    mon_ip_ids = ""
    for key, val in mon_ips_dict.items():
        mon_ip_ids = mon_ip_ids + f"--addv {key} {val}" + " "

    mon_map_cmd = f"monmaptool --create {mon_ip_ids} --enable-all-features --clobber /tmp/monmap --fsid {fsid}"
    return mon_map_cmd