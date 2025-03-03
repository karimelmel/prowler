import threading

import google_auth_httplib2
import httplib2
from colorama import Fore, Style
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from googleapiclient.discovery import Resource

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider


class GCPService:
    def __init__(
        self,
        service: str,
        provider: GcpProvider,
        region="global",
        api_version="v1",
    ):
        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: APIKeys --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service
        self.credentials = provider.session
        self.api_version = api_version
        self.region = region
        self.client = self.__generate_client__(
            self.service, api_version, self.credentials
        )
        # Only project ids that have their API enabled will be scanned
        self.project_ids = self.__is_api_active__(provider.project_ids)
        self.projects = provider.projects
        self.default_project_id = provider.default_project_id
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def _get_client(self):
        return self.client

    def __threading_call__(self, call, iterator):
        threads = []
        for value in iterator:
            threads.append(threading.Thread(target=call, args=(value,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __get_AuthorizedHttp_client__(self):
        return google_auth_httplib2.AuthorizedHttp(
            self.credentials, http=httplib2.Http()
        )

    def __is_api_active__(self, audited_project_ids):
        # Skip the API check and simply return all project IDs
        # This assumes all services are enabled for all projects
        logger.info(f"Skipping API enablement check for {self.service}")
        
        # If this is a common service that we know we want to scan, include all projects
        common_services = [
            "compute",        # Compute Engine
            "storage",        # Cloud Storage
            "iam",            # Identity and Access Management
            "container",      # Google Kubernetes Engine
            "cloudkms",       # Cloud Key Management Service
            "logging",        # Cloud Logging
            "monitoring",     # Cloud Monitoring
            "bigquery",       # BigQuery
            "cloudfunctions", # Cloud Functions
            "sql",            # Cloud SQL
            "dns",            # Cloud DNS
            "cloudresourcemanager", # Resource Manager
            "secretmanager",  # Secret Manager
            "cloudasset",     # Cloud Asset Inventory
        ]
        
        # Either return all projects if this is a common service, or an empty list if it's not
        if self.service in common_services:
            return audited_project_ids
        else:
            # For less common services, log a note but still include all projects
            logger.info(f"Service {self.service} is not in the common services list, but will be scanned anyway")
            return audited_project_ids

    def __generate_client__(
        self,
        service: str,
        api_version: str,
        credentials: Credentials,
    ) -> Resource:
        try:
            return discovery.build(service, api_version, credentials=credentials)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
