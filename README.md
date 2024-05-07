# ADF Linter
The main objective of this project is to aid the Codebase Governance for Azure Data Factory (ADF) Pipelines. The Governance aims to control the _Cost, Performance, Maintainability, and Security_ of each ADF Pipeline.

## Checks Performed ✅
This project uses Regex pattern matching and a Simple Hash Table traversal to do the checks. Below are the Checks Supported:

| Check Name                                           | Description                                                                                          |
|------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| check_linked_services_using_key_vault                | Linked Service(s) not using Azure Key Vault to store credentials.                                    |
| check_pipelines_not_in_folder                        | Pipeline(s) not organised into folders.                                                              |
| check_activity_timeout_values                        | Activities with timeout values still set to the service default value of 7 days.                     |
| check_copy_activity_diu_values                       | Activities with DIU (Data Integration Units) values still set to the service default value of 'Auto' |
| check_orphaned_linked_services                       | Linked Service(s) not used by any other resource.                                                    |
| check_orphaned_dataset                               | Dataset(s) not used by any other resource.                                                           |
| check_datasets_not_in_folder                         | Dataset(s) not organised into folders.                                                               |
| check_orphaned_triggers                              | Trigger(s) not used by any other resource.                                                           |
| check_master_pipeline_without_triggers               | Master Pipeline(s) without any triggers attached. Directly or indirectly.                            |
| check_pipeline_impossible_execution_chain            | Pipeline(s) with an impossible AND/OR activity execution chain.                                      |
| check_pipeline_descriptions                          | Pipeline(s) without a description value.                                                             |
| check_pipelines_without_annotation                   | Pipeline(s) without annotations.                                                                     |
| check_data_flow_descriptions                         | Data Flow(s) without a description value.                                                            |
| check_activity_description                           | Activities without a description value.                                                              |
| check_foreach_batch_size_unset                       | Activities ForEach iteration without a batch count value set.                                        |
| check_foreach_activity_batch_size_lt_service_maximum | Activities ForEach iteration with a batch count size that is less than the service maximum.          |
| check_linked_services_has_description                | Linked Service(s) without a description value.                                                       |
| check_linked_services_has_annotation                 | Linked Service(s) without annotations.                                                               |
| check_datasets_without_description                   | Dataset(s) without a description value.                                                              |
| check_datasets_without_annotation                    | Dataset(s) without annotations.                                                                      |
| check_triggers_has_description                       | Trigger(s) without a description value.                                                              |
| check_triggers_without_annotation                    | Trigger(s) without annotations.                                                                      |

## Linter in Action

![ADF Linter In Action](images/adf_linter_in_action.gif)

## Quick Start

1. First, go to your ADF instance and navigate `Manage -> ARM template` then Export ARM template. It should give you a zip file with **ARMTemplateForFactory.json** inside it, save that json file.
2. Now, install the adf-lint package in your machine
    ```commandline
    pip install git+https://github.com/1byte-yoda/adf-lint.git@master
    ```
3. Once you have successfully installed the **adf-lint** package, you can test it by running:
   ```commandline
   adf_checker lint --arm_template=ARMTemplateForFactory.json --verbose=0 --assertion=y
   ```

### Getting Help with the Lint Command
```commandline
adf_checker lint --help
```

### Listing All Available Checks
```commandline
adf_checker list_check_names
```

## Contributing to Development

Clone the repository
```commandline
https://github.com/1byte-yoda/adf-lint.git
```

Installing from source [Develop Mode]
```commandline
pip install -e .
```

Testing the Linter
```commandline
adf_checker lint --arm_template=test_template.json --verbose=0
```

## Future Improvements
- Automate the Arm Template export using Azure Management API
- Publicly host this package into Pypi
