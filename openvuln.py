"""
Creates a Vulnerability Report for the devices specified in the inventory,
using the Cisco openVuln API to retrieve Advisories for all found Operating System Versions.
"""

# Imports
import copy
from datetime import datetime
from getpass import getpass
from time import sleep
from nornir import InitNornir
from nornir.core.task import Task
from nornir_netmiko.tasks import netmiko_send_command
from nornir_utils.plugins.functions import print_result
import requests
import jinja2

# Constants
IOS = "ios"
IOS_XE = "iosxe"
NXOS = "nxos"


def openvuln_login(client_id: str, client_secret: str) -> dict:
    """
    Log in to the Cisco PSIRT openVuln API.

    Returns a dict containing an access token and token type,
    accessible via dict["access_token] and dict["token_type"]
    """

    url = "https://cloudsso.cisco.com/as/token.oauth2"
    payload = f"client_id={client_id}&client_secret={client_secret}&grant_type=client_credentials"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.request("POST", url, headers=headers, data=payload)
    response.raise_for_status()

    return response.json()


def get_api_formatted_os(os_name: str) -> str:
    """
    Transforms the OS name returned from the devices into
    a format which can be used to build the API queries.
    """

    if os_name.lower() == "ios":
        return IOS
    if os_name.lower() == "ios-xe":
        return IOS_XE
    if os_name.lower() == "nx-os":
        return NXOS
    raise ValueError(
        "The provided OS Name does not match any known pattern. Expecting ios, ios-xe or nxos."
    )


def get_openvuln_by_os_version(os_versions: dict, access_dict: dict) -> dict:
    """
    Queries the Cisco PSIRT openVuln API for Security Advisories
    for the given OS / Version combinations.
    Input: {(os, version): {"hosts":[]}}
    Output: {(os, version): {"hosts":[], "advisories":[]}}
    """

    base_url = "https://api.cisco.com/security/advisories/"

    advisories = copy.deepcopy(os_versions)

    # check if we need to limit our queries.
    # the API allows only for 10 requests/sec
    ratelimit = len(advisories) > 10

    for os, version in advisories.keys():
        os_api_name = get_api_formatted_os(os)
        url = base_url + f"{os_api_name}?version={version}"
        payload = {}
        headers = {
            "Authorization": f'{access_dict["token_type"]} {access_dict["access_token"]}'
        }

        response = requests.request("GET", url, headers=headers, data=payload)
        response.raise_for_status()

        for advisory in response.json()["advisories"]:
            advisories[(os, version)]["advisories"] = advisories[(os, version)].get(
                "advisories", []
            )
            advisories[(os, version)]["advisories"].append(
                {
                    "advisoryId": advisory.get("advisoryId"),
                    "cves": advisory.get("cves", "n/a"),
                    "cvssBaseScore": float(advisory.get("cvssBaseScore", 0)),
                    "firstFixed": advisory.get("firstFixed", "n/a"),
                    "sir": advisory.get("sir", "n/a"),
                    "publicationUrl": advisory.get("publicationUrl", "n/a"),
                }
            )
        # if we have a lot of os versions to query, we want to
        # limit the rate at which we query the API.
        # (it allows only for 10 requests per second)
        if ratelimit:
            sleep(0.12)

    return advisories


def get_ios_xe_version(task: Task) -> dict:
    """
    get the IOS version of a device
    """

    result = task.run(
        task=netmiko_send_command, command_string="show version", use_genie=True
    )

    os = result.result["version"]["os"]
    version = result.result["version"]["version"]

    return {"os": os, "version": version}


def get_nxos_version(task: Task) -> dict:
    """
    get the NX-OS version of a device
    """
    result = task.run(
        task=netmiko_send_command, command_string="show version", use_genie=True
    )

    os = result.result["platform"]["os"]
    version = result.result["platform"]["software"]["system_version"]

    return {"os": os, "version": version}


def results_to_host_version(result_list: list) -> dict:
    """
    Takes a list of nornir Result elements and returns a dict with
    hostnames as keys and dicts {"os":os, "version":version} as values.
    """

    host_os_version = {}

    for result in result_list:
        for host in result:
            # skip to next host if result.failed is True
            if result[host].failed:
                print(
                    f"The result object for {host} indicates that something went wrong.\n"
                    + f"{host} will be excluded from the report."
                )
                print_result(result[host])
                continue
            host_os_version[host] = {}
            os = result[host][0].result["os"]
            version = result[host][0].result["version"]
            host_os_version[host] = (os, version)

    return host_os_version


def pivot_on_version(host_version_dict: dict) -> dict:
    """
    takes a dictionary of {host:(os, version)},
    returns a dict of {(os, version):[hosts]}
    """

    os_version_host_dict = {}
    for host, os_version in host_version_dict.items():
        os_version_host_dict[os_version] = os_version_host_dict.get(
            os_version, {"hosts": []}
        )
        os_version_host_dict[os_version]["hosts"].append(host)

    return os_version_host_dict


def render_report(os_version_vuln: dict) -> None:
    """
    Render the report and save it to './openvuln.md'
    """

    template_loader = jinja2.FileSystemLoader(searchpath="./")
    template_env = jinja2.Environment(
        loader=template_loader, trim_blocks=True, lstrip_blocks=True
    )
    template_file = "openvuln.md.j2"
    template = template_env.get_template(template_file)
    rendered = template.render(
        os_version_vuln=os_version_vuln,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    with open("openvuln.md", "w") as file:
        file.write(rendered)


def main() -> None:
    """
    client_id = getpass(prompt="client_id: ")
    client_secret = getpass(prompt="client_secret: ")
    access_dict = openvuln_login(client_id=client_id, client_secret=client_secret)
    print(access_dict["access_token"])
    """

    access_dict = openvuln_login(
        getpass("Enter client_id: "), getpass("Enter client_secret: ")
    )

    nornir = InitNornir(config_file="config.yaml")

    ios_xe_targets = nornir.filter(platform="cisco_xe")
    ios_xe_results = ios_xe_targets.run(task=get_ios_xe_version)

    nxos_targets = nornir.filter(platform="nxos")
    nxos_results = nxos_targets.run(task=get_nxos_version)

    result_list = [ios_xe_results, nxos_results]
    
    #for result in result_list:
    #    print_result(result)

    host_os_version = results_to_host_version(result_list=result_list)
    os_version_host_dict = pivot_on_version(host_os_version)

    os_version_vuln = get_openvuln_by_os_version(
        os_versions=os_version_host_dict, access_dict=access_dict
    )

    render_report(os_version_vuln=os_version_vuln)


if __name__ == "__main__":
    main()
