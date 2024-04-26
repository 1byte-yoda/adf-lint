from colorama import Fore, Style


def clean_name(raw_value):
    """Get the string between '/' and '"' characters"""
    slash_index = raw_value.find("/") + 1
    last_quote_index = raw_value.rfind("'")
    return raw_value[slash_index:last_quote_index]


def clean_type(raw_value):
    """Get the string starting from the forward slash"""
    last_slash_index = raw_value.rfind("/") + 1
    return raw_value[last_slash_index:]


def get_resource_dependants(adf: dict, triggers: list[dict]):
    resources_list = []
    dependants_list = []

    for resource in adf['resources']:
        resource_name = clean_name(resource['name'])
        resource_type = clean_type(resource['type'])
        complete_resource = resource_type + "|" + resource_name

        if complete_resource not in resources_list:
            resources_list.append(complete_resource)

    for resource in adf['resources']:
        if 'dependsOn' in resource and len(resource['dependsOn']) == 1:
            dependant_name = clean_name(str(resource['dependsOn'][0]))
            complete_dependant = dependant_name.replace('/', '|')

            if complete_dependant not in dependants_list:
                dependants_list.append(complete_dependant)
        elif 'dependsOn' in resource:
            for dependant in resource['dependsOn']:
                dependant_name = clean_name(dependant)
                complete_dependant = dependant_name.replace('/', '|')

                if complete_dependant not in dependants_list:
                    dependants_list.append(complete_dependant)

    for resource in triggers:
        resource_name = clean_name(resource['name'])
        resource_type = clean_type(resource['type'])
        complete_resource = resource_type + "|" + resource_name

        if 'dependsOn' in resource and len(resource['dependsOn']) >= 1:
            if complete_resource not in dependants_list:
                dependants_list.append(complete_resource)

    return [res for res in resources_list if res not in dependants_list]


def get_colored_severity(severity: str):
    match severity:
        case "Low":
            return f"{Fore.LIGHTBLUE_EX}{severity}{Style.RESET_ALL}"
        case "Medium":
            return f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
        case "High":
            return f"{Fore.RED}{severity}{Style.RESET_ALL}"


def is_sensitive_property(name: str):
    lowered_name = name.lower()
    return (
            "key" in lowered_name
            or "secret" in lowered_name
            or "password" in lowered_name
            or "token" in lowered_name
    )
