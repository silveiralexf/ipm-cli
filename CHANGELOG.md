# v0.1.0

### Binaries

[ipm-cli_v0.1.0](https://github.com/fsilveir/ipm-cli/releases/tag/v0.1.0)

### Changelog

- Improved README with more instructions and added CHANGELOG for better version control.

- Added a new functionality to Add/Remove an agent from Resource Groups

- Included an additional check to confirm if the the API response is empty for the *_uiThresholdType* key. This is due to a known problem that fails to populate this field correctly for some GSMA Monitoring Agents, this problem was fixed on the latest release of APM, but this additional verification was included to set the value to unknown in case the API responds an empty value to avoid unwanted error messages on older versions.

- Included an additional error message for failed login, this way users can identify that the login failed due to invalid credentials and when the login failed due to another generic HTTP error.

- Included additional exceptions to help the user to differenciate HTTP from SSL errors.

- Instead of making a request to the **mgmt_artifacts** to verify if connection was successfully established, updated the script to look the first threshold instead, since in case there are no agents connected to the subscription the script would not be able to successfully login -- also, this call is faster, since it only searches for the first item of the list instead of the previous call that was listing all available items (which could take some additional seconds to finish).
