from dataclasses import dataclass
import json
import sys

from tabulate import tabulate
from colorama import Style
from dataclasses_json import LetterCase, DataClassJsonMixin, config

from adf_lint.helper import clean_name, get_resource_dependants, get_colored_severity, is_sensitive_property


@dataclass
class ADFObject(DataClassJsonMixin):
    dataclass_json_config = config(letter_case=LetterCase.CAMEL, undefined=None)

    name: str
    type: str
    api_version: str
    properties: str
    depends_on: str


@dataclass
class ARMTemplate(DataClassJsonMixin):
    linked_services: list[ADFObject]
    datasets: list[ADFObject]
    pipelines: list[ADFObject]
    activities: list[ADFObject]
    dataflows: list[ADFObject]
    triggers: list[ADFObject]


class ADFLintChecker:
    def __init__(self, verbose: bool, ignore_assertion: bool):
        self.check_number = 0
        self.summary_table = []
        self.verbose_detail_table = []
        self.verbose = verbose
        self.ignore_assertion = ignore_assertion

    @staticmethod
    def read_arm_template(path: str) -> dict:
        with open(path, 'r') as f:
            return json.load(f)

    def log_summary_table(self):
        if self.verbose:
            print(f"\n{Style.BRIGHT}Check Details:{Style.RESET_ALL}")
            component = [detail['Component'] for detail in self.verbose_detail_table]
            name = [detail['Name'] for detail in self.verbose_detail_table]
            check_details = [detail['CheckDetail'] for detail in self.verbose_detail_table]
            severity_colored = [get_colored_severity(detail["Severity"]) for detail in self.verbose_detail_table]

            print(tabulate({"Component": component, "Name": name, "Check Detail": check_details, "Severity": severity_colored}, tablefmt="psql", headers="keys"))

        print(f"\n{Style.BRIGHT}Check Summary:{Style.RESET_ALL}")
        summary_table = {"Issue Count": [], "Check Details": [], "Severity": []}
        for item in self.summary_table:
            if item['IssueCount'] != 0:
                summary_table["Issue Count"].append(item['IssueCount'])
                summary_table["Check Details"].append(item['CheckDetail'])
                summary_table["Severity"].append(get_colored_severity(item['Severity']))
        print(tabulate(summary_table, tablefmt="psql", headers="keys"))

        print(f"\n{Style.BRIGHT}Results Summary:{Style.RESET_ALL}")
        print("Checks ran against template:", self.check_number)
        checks_with_issues = sum(1 for item in self.summary_table if item['IssueCount'] != 0)
        total_issue_count = sum(item['IssueCount'] for item in self.summary_table)
        print("Checks with issues found:", checks_with_issues)
        print("Total issue count:", total_issue_count)

    def log_check_output(self):
        if self.verbose:
            print("Verbose Details:")
            for detail in self.verbose_detail_table:
                print(detail)

    def assert_adf_lint_free(self):
        if not self.ignore_assertion:
            has_errors = len(self.verbose_detail_table) > len(self.summary_table) > 0
            sys.exit(has_errors)

    @classmethod
    def get_check_names(cls):
        return [func for func in dir(cls) if callable(getattr(cls, func)) and func.startswith("check_")]

    def main(self, path: str):
        adf = self.read_arm_template(path=path)

        linked_services = [res for res in adf['resources'] if res['type'] == "Microsoft.DataFactory/factories/linkedServices"]
        datasets = [res for res in adf['resources'] if res['type'] == "Microsoft.DataFactory/factories/datasets"]
        pipelines = [res for res in adf['resources'] if res['type'] == "Microsoft.DataFactory/factories/pipelines"]
        activities = [(pipeline['properties']["folder"]["name"], p) for pipeline in pipelines for p in pipeline['properties']["activities"]]
        dataflows = [res for res in adf['resources'] if res['type'] == "Microsoft.DataFactory/factories/dataflows"]
        triggers = [res for res in adf['resources'] if res['type'] == "Microsoft.DataFactory/factories/triggers"]

        redundant_resources = get_resource_dependants(adf=adf, triggers=triggers)

        self.check_master_pipeline_without_triggers(redundant_resources=redundant_resources)
        self.check_pipeline_impossible_execution_chain(pipelines=pipelines)
        self.check_pipeline_descriptions(pipelines=pipelines)
        self.check_pipelines_not_in_folder(pipelines=pipelines)
        self.check_pipelines_without_annotation(pipelines=pipelines)
        self.check_data_flow_descriptions(dataflows=dataflows)
        self.check_activity_timeout_values(activities=activities)
        self.check_copy_activity_diu_values(activities=activities)
        self.check_activity_description(activities=activities)
        self.check_foreach_batch_size_unset(activities=activities)
        self.check_foreach_activity_batch_size_lt_service_maximum(activities=activities)
        self.check_linked_services_using_key_vault(linked_services=linked_services)
        self.check_orphaned_linked_services(redundant_resources=redundant_resources)
        self.check_linked_services_has_description(linked_services=linked_services)
        self.check_linked_services_has_annotation(linked_services=linked_services)
        self.check_orphaned_dataset(redundant_resources=redundant_resources)
        self.check_datasets_without_description(datasets=datasets)
        self.check_datasets_not_in_folder(datasets=datasets)
        self.check_datasets_without_annotation(datasets=datasets)
        self.check_orphaned_triggers(redundant_resources=redundant_resources)
        self.check_triggers_has_description(triggers=triggers)
        self.check_triggers_without_annotation(triggers=triggers)

        self.log_summary_table()
        self.assert_adf_lint_free()

    def check_master_pipeline_without_triggers(self, redundant_resources: list[str]):
        self.check_number += 1
        check_detail = "Master Pipeline(s) without any triggers attached. Directly or indirectly."
        print("Running check...", check_detail)
        severity = "Medium"
        check_counter = 0

        for redundant_resource in [r for r in redundant_resources if r.startswith("pipelines") and "master" in r]:
            parts = redundant_resource.split('|')

            check_counter += 1
            if self.verbose:
                self.verbose_detail_table.append({
                    "Component": "Pipeline",
                    "Name": parts[1],
                    "CheckDetail": "Does not have any triggers attached.",
                    "Severity": severity
                })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_pipeline_impossible_execution_chain(self, pipelines: list[dict]):
        self.check_number += 1
        check_detail = "Pipeline(s) with an impossible AND/OR activity execution chain."
        print("Running check...", check_detail)
        severity = "High"
        check_counter = 0

        for pipeline in pipelines:
            pipeline_name = clean_name(pipeline['name'])
            activity_failure_dependencies = []
            activity_success_dependencies = []

            for activity in pipeline['properties']['activities']:
                if 'dependsOn' in activity and len(activity['dependsOn']) > 1:
                    for up_stream_activity in activity['dependsOn']:
                        if 'Failed' in up_stream_activity['dependencyConditions']:
                            if up_stream_activity['activity'] not in activity_failure_dependencies:
                                activity_failure_dependencies.append(up_stream_activity['activity'])

            for activity_dependant in activity_failure_dependencies:
                for activity in [act for act in pipeline['properties']['activities'] if act['name'] == activity_dependant]:
                    if 'dependsOn' in activity and len(activity['dependsOn']) >= 1:
                        for down_stream_activity in activity['dependsOn']:
                            if 'Succeeded' in down_stream_activity['dependencyConditions']:
                                if down_stream_activity['activity'] not in activity_success_dependencies:
                                    activity_success_dependencies.append(down_stream_activity['activity'])

            problems = [problem for problem in activity_failure_dependencies if problem in activity_success_dependencies]
            if problems:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Pipeline",
                        "Name": pipeline_name,
                        "CheckDetail": "Has an impossible AND/OR activity execution chain.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_pipeline_descriptions(self, pipelines):
        self.check_number += 1
        check_detail = "Pipeline(s) without a description value."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for pipeline in pipelines:
            pipeline_name = clean_name(pipeline['name'])
            pipeline_description = pipeline['properties'].get('description', '')

            if not pipeline_description:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Pipeline",
                        "Name": pipeline_name,
                        "CheckDetail": "Does not have a description.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_pipelines_not_in_folder(self, pipelines):
        self.check_number += 1
        check_detail = "Pipeline(s) not organised into folders."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for pipeline in pipelines:
            pipeline_name = clean_name(pipeline['name'])
            pipeline_folder = pipeline['properties'].get('folder', {}).get('name', '')

            if not pipeline_folder:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Pipeline",
                        "Name": pipeline_name,
                        "CheckDetail": "Not organised into a folder.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_pipelines_without_annotation(self, pipelines: list[dict]):
        self.check_number += 1
        check_detail = "Pipeline(s) without annotations."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for pipeline in pipelines:
            pipeline_name = clean_name(pipeline['name'])
            pipeline_annotations = len(pipeline['properties'].get('annotations', []))

            if pipeline_annotations <= 0:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Pipeline",
                        "Name": pipeline_name,
                        "CheckDetail": "Does not have any annotations.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_data_flow_descriptions(self, dataflows):
        self.check_number += 1
        check_detail = "Data Flow(s) without a description value."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for data_flow in dataflows:
            data_flow_name = clean_name(data_flow['name'])
            data_flow_description = data_flow['properties'].get('description', '')

            if not data_flow_description:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Data Flow",
                        "Name": data_flow_name,
                        "CheckDetail": "Does not have a description.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_copy_activity_diu_values(self, activities):
        self.check_number += 1
        check_detail = "Activities with DIU (Data Integration Units) values still set to the service default value of 'Auto'"
        print("Running check...", check_detail)
        severity = "High"
        check_counter = 0

        for folder_name, activity in activities:
            if 'policy' in activity and 'timeout' in activity['policy']:
                diu = activity["typeProperties"].get("dataIntegrationUnits")
                activity_type = activity["type"]
                if activity_type == "Copy" and diu is None:
                    check_counter += 1
                    if self.verbose:
                        self.verbose_detail_table.append({
                            "Component": "Activity",
                            "Name": f"{folder_name}/{activity.get('name', 'Unnamed Activity')}",
                            "CheckDetail": "DIU still set to the service default value of 'Auto'.",
                            "Severity": severity
                        })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_activity_timeout_values(self, activities):
        self.check_number += 1
        check_detail = "Activities with timeout values still set to the service default value of 7 days."
        print("Running check...", check_detail)
        severity = "High"
        check_counter = 0

        for activity in activities:
            if 'policy' in activity and 'timeout' in activity['policy']:
                timeout = activity['policy']['timeout']
                if timeout and timeout == "7.00:00:00":
                    check_counter += 1
                    if self.verbose:
                        self.verbose_detail_table.append({
                            "Component": "Activity",
                            "Name": activity.get('name', 'Unnamed Activity'),
                            "CheckDetail": "Timeout policy still set to the service default value of 7 days.",
                            "Severity": severity
                        })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_activity_description(self, activities):
        self.check_number += 1
        check_detail = "Activities without a description value."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for activity in activities:
            activity_description = activity.get('description', '')

            if not activity_description:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Activity",
                        "Name": activity.get('name', 'Unnamed Activity'),
                        "CheckDetail": "Does not have a description.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_foreach_batch_size_unset(self, activities):
        self.check_number += 1
        check_detail = "Activities ForEach iteration without a batch count value set."
        print("Running check...", check_detail)
        severity = "High"
        check_counter = 0

        for activity in [act for act in activities if act.get('type') == 'ForEach']:
            is_sequential = activity['typeProperties'].get('isSequential', False)
            batch_count = activity['typeProperties'].get('batchCount', '')

            if not is_sequential:
                if not batch_count:
                    check_counter += 1
                    if self.verbose:
                        self.verbose_detail_table.append({
                            "Component": "Activity",
                            "Name": activity.get('name', 'Unnamed ForEach Activity'),
                            "CheckDetail": "ForEach does not have a batch count value set.",
                            "Severity": severity
                        })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_foreach_activity_batch_size_lt_service_maximum(self, activities):
        self.check_number += 1
        check_detail = "Activities ForEach iteration with a batch count size that is less than the service maximum."
        print("Running check...", check_detail)
        severity = "Medium"
        check_counter = 0

        for activity in [act for act in activities if act.get('type') == 'ForEach']:
            is_sequential = activity['typeProperties'].get('isSequential', False)
            batch_count = activity['typeProperties'].get('batchCount', None)

            if not is_sequential and batch_count is not None and int(batch_count) < 50:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Activity",
                        "Name": activity.get('name', 'Unnamed ForEach Activity'),
                        "CheckDetail": "ForEach has a batch size that is less than the service maximum.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_linked_services_using_key_vault(self, linked_services):
        self.check_number += 1
        check_detail = "Linked Service(s) not using Azure Key Vault to store credentials."
        print("Running check...", check_detail)
        severity = "High"

        linked_service_list = []

        for linked_service in [ls for ls in linked_services if ls['properties']['type'] != "AzureKeyVault"]:
            for prop_name, prop_value in linked_service['properties']['typeProperties'].items():
                if 'secretName' not in str(prop_value) and is_sensitive_property(name=prop_name):
                    linked_service_name = f"{clean_name(linked_service['name'])} -> {prop_name}"
                    if linked_service_name not in linked_service_list:
                        linked_service_list.append(linked_service_name)
                else:
                    linked_service_name = clean_name(linked_service['name'])
                    if linked_service_name in linked_service_list:
                        linked_service_list.remove(linked_service_name)

        check_counter = len(linked_service_list)
        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        if self.verbose:
            for linked_service_output in linked_service_list:
                self.verbose_detail_table.append({
                    "Component": "Linked Service",
                    "Name": linked_service_output,
                    "CheckDetail": "Not using Key Vault to store credentials.",
                    "Severity": severity
                })

        self.log_check_output()

    def check_orphaned_linked_services(self, redundant_resources):
        self.check_number += 1
        check_detail = "Linked Service(s) not used by any other resource."
        print("Running check...", check_detail)
        severity = "Medium"
        check_counter = 0

        for redundant_resource in [r for r in redundant_resources if r.startswith("linkedServices")]:
            parts = redundant_resource.split('|')

            check_counter += 1
            if self.verbose:
                self.verbose_detail_table.append({
                    "Component": "Linked Service",
                    "Name": parts[1],
                    "CheckDetail": "Not used by any other resource.",
                    "Severity": severity
                })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_linked_services_has_description(self, linked_services):
        self.check_number += 1
        check_detail = "Linked Service(s) without a description value."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for linked_service in linked_services:
            linked_service_name = clean_name(linked_service['name'])
            linked_service_description = linked_service['properties'].get('description', '')

            if not linked_service_description:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Linked Service",
                        "Name": linked_service_name,
                        "CheckDetail": "Does not have a description.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_linked_services_has_annotation(self, linked_services):
        self.check_number += 1
        check_detail = "Linked Service(s) without annotations."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for linked_service in linked_services:
            linked_service_name = clean_name(linked_service['name'])
            linked_service_annotations = len(linked_service['properties'].get('annotations', []))

            if linked_service_annotations <= 0:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Linked Service",
                        "Name": linked_service_name,
                        "CheckDetail": "Does not have any annotations.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_orphaned_dataset(self, redundant_resources):
        self.check_number += 1
        check_detail = "Dataset(s) not used by any other resource."
        print("Running check...", check_detail)
        severity = "Medium"
        check_counter = 0

        for redundant_resource in [r for r in redundant_resources if r.startswith("datasets")]:
            parts = redundant_resource.split('|')

            check_counter += 1
            if self.verbose:
                self.verbose_detail_table.append({
                    "Component": "Dataset",
                    "Name": parts[1],
                    "CheckDetail": "Not used by any other resource.",
                    "Severity": severity
                })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_datasets_without_description(self, datasets):
        self.check_number += 1
        check_detail = "Dataset(s) without a description value."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for dataset in datasets:
            dataset_name = clean_name(dataset['name'])
            dataset_description = dataset['properties'].get('description', '')

            if not dataset_description:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Dataset",
                        "Name": dataset_name,
                        "CheckDetail": "Does not have a description.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_datasets_not_in_folder(self, datasets):
        self.check_number += 1
        check_detail = "Dataset(s) not organised into folders."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for dataset in datasets:
            dataset_name = clean_name(dataset['name'])
            dataset_folder = dataset['properties'].get('folder', {}).get('name', '')

            if not dataset_folder:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Dataset",
                        "Name": dataset_name,
                        "CheckDetail": "Not organised into a folder.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_datasets_without_annotation(self, datasets):
        self.check_number += 1
        check_detail = "Dataset(s) without annotations."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for dataset in datasets:
            dataset_name = clean_name(dataset['name'])
            dataset_annotations = len(dataset['properties'].get('annotations', []))

            if dataset_annotations <= 0:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Dataset",
                        "Name": dataset_name,
                        "CheckDetail": "Does not have any annotations.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_orphaned_triggers(self, redundant_resources):
        self.check_number += 1
        check_detail = "Trigger(s) not used by any other resource."
        print("Running check...", check_detail)
        severity = "Medium"
        check_counter = 0

        for redundant_resource in [r for r in redundant_resources if r.startswith("triggers")]:
            parts = redundant_resource.split('|')

            check_counter += 1
            if self.verbose:
                self.verbose_detail_table.append({
                    "Component": "Trigger",
                    "Name": parts[1],
                    "CheckDetail": "Not used by any other resource.",
                    "Severity": severity
                })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_triggers_has_description(self, triggers):
        self.check_number += 1
        check_detail = "Trigger(s) without a description value."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for trigger in triggers:
            trigger_name = clean_name(trigger['name'])
            trigger_description = trigger['properties'].get('description', '')

            if not trigger_description:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Trigger",
                        "Name": trigger_name,
                        "CheckDetail": "Does not have a description.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()

    def check_triggers_without_annotation(self, triggers):
        self.check_number += 1
        check_detail = "Trigger(s) without annotations."
        print("Running check...", check_detail)
        severity = "Low"
        check_counter = 0

        for trigger in triggers:
            trigger_name = clean_name(trigger['name'])
            trigger_annotations = len(trigger['properties'].get('annotations', []))

            if trigger_annotations <= 0:
                check_counter += 1
                if self.verbose:
                    self.verbose_detail_table.append({
                        "Component": "Trigger",
                        "Name": trigger_name,
                        "CheckDetail": "Does not have any annotations.",
                        "Severity": severity
                    })

        self.summary_table.append({
            "IssueCount": check_counter,
            "CheckDetail": check_detail,
            "Severity": severity
        })

        self.log_check_output()