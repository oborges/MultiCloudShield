"""Read-only Azure provider adapter.

Azure SDK imports are intentionally isolated in :mod:`clients` and happen only when a
live connection is used. Importing the application never requires Azure packages or
credentials.
"""

from multicloudshield.providers.azure.adapter import AzureAdapter

__all__ = ["AzureAdapter"]
