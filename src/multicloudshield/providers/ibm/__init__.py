"""IBM Cloud provider adapter.

The module intentionally imports no IBM SDK. SDK imports live behind the lazy client factory so
API-process imports and installations without the optional ``ibm`` extra remain safe.
"""

from multicloudshield.providers.ibm.adapter import IbmAdapter

__all__ = ["IbmAdapter"]
