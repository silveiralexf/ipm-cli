# Changelog

This file contains the release notes for the previous releases, and the ongoing work for the next releases.

## v0.5.2

Released on **Feb/19/2019**.

-   Improved error message for RG add/remove failures


## v0.5.1

Released on **Feb/02/2019**.

-   Fixed [Issue #7](https://github.com/fsilveir/ipm-cli/issues/7)

## v0.5.0

Released on **Jan/31/2019**.

-   Fixed duplicated error message on login steps (error was happening after a failed login followed by a successfull one).
-   Improved file handling with new function for checking out after errors.
-   Included requirements.txt file.
-   Increased session timeout from 120min to 240min
-   Included try statement to catch exceptions during session validation when token was expired due to network issues.
-   Added a functionality to add / remove a threshold to / from a Resource Group.
-   Updated some INFO/ERROR messages display and usage instructions to fit the same pattern.
-   Fixed error handling of missing KeyIndex value on Agents.get_agents function
-   Refactored multiple try/except statements to avoid exceptions
-   Fixed bug related to special characters in password that would cause an exception on IPM Private subscriptions.
-   Added / improved comments to better document the code.


## v0.4.0

Released on **Nov/24/2018**.

-   Removed unrequired variable on exception check and useless pass statement
-   Added new functionality to display list of thresholds by Resource Group id.
-   Updated markdown formatting and usage instructions.

## v0.3.0

Released on **Nov/21/2018**.

-   Added an exception to avoid unwanted error message when checking IPM subscriptions without any Resource Groups created.
-   Added the functionality to create a new threshold from a JSON file.
-   Added functionality to delete a threshold by name.
-   Updated main menu descriptions and error messages.

## v0.2.0

Released on **Nov/18/2018**.

-   Refactored the script to use classes for better organizing the code and simplify requests.
-   Implemented new functionality to export list of thresholds to JSON (`ipm get thr -f`).
-   Changed default request timeout from 30 to 60 seconds to accomodate bigger subscriptions.
-   Fixed bug on login function, on which users could input an invalid region.
-   Added a new region for Latin America (`la`) to the interactive login option.
-   Updated name of multiple methods to improve readability. 
-   Added/Updated multiple comments to improve readability.
-   Changed imports to separate lines instead of using all in a single line, as recommended by [PEP 8](https://www.python.org/dev/peps/pep-0008/).

## v0.1.0

Released on **Nov/06/2018**.

-   Improved README with more instructions and added CHANGELOG for better version control.
-   Added a new functionality to Add/Remove an agent from Resource Groups
-   Included an additional check to confirm if the the API response is empty for the _\_uiThresholdType_ key. This is due to a known problem that fails to populate this field correctly for some GSMA Monitoring Agents, this problem was fixed on the latest release of APM, but this additional verification was included to set the value to unknown in case the API responds an empty value to avoid unwanted error messages on older versions.
-   Included an additional error message for failed login, this way users can identify that the login failed due to invalid credentials and when the login failed due to another generic HTTP error.
-   Included additional exceptions to help the user to differenciate HTTP from SSL errors.
-   Instead of making a request to the **mgmt_artifacts** to verify if connection was successfully established, updated the script to look the first threshold instead, since in case there are no agents connected to the subscription the script would not be able to successfully login - \*  also, this call is faster, since it only searches for the first item of the list instead of the previous call that was listing all available items (which could take some additional seconds to finish).
