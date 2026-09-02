from __future__ import annotations

from mcp_common.operations import StrictModel


class OrganizationObservation(StrictModel):
    federation_enabled: bool | None = None
    oauth2_client_profile_enabled: bool | None = None
    public_folders_enabled: str = ""
    public_folder_mailboxes_migration_complete: bool | None = None
    focused_inbox_enabled: bool | None = None


class AcceptedDomainObservation(StrictModel):
    domain_ref: str
    domain_name: str | None = None
    domain_type: str = ""
    default: bool | None = None
    address_book_enabled: bool | None = None
    match_subdomains: bool | None = None


class RemoteDomainObservation(StrictModel):
    domain_ref: str
    domain_name: str | None = None
    allowed_oof_type: str = ""
    auto_forward_enabled: bool | None = None
    auto_reply_enabled: bool | None = None
    delivery_report_enabled: bool | None = None
    ndr_enabled: bool | None = None
    tnef_enabled: bool | None = None


class InboundConnectorObservation(StrictModel):
    connector_ref: str
    enabled: bool | None = None
    connector_type: str = ""
    require_tls: bool | None = None
    restrict_domains_to_certificate: bool | None = None
    restrict_domains_to_ip_addresses: bool | None = None
    cloud_services_mail_enabled: bool | None = None
    treat_messages_as_internal: bool | None = None
    sender_ip_count: int = 0
    sender_domain_count: int = 0


class OutboundConnectorObservation(StrictModel):
    connector_ref: str
    enabled: bool | None = None
    connector_type: str = ""
    route_all_messages_via_on_premises: bool | None = None
    use_mx_record: bool | None = None
    tls_settings: str = ""
    recipient_domain_count: int = 0
    smart_host_count: int = 0


class TransportConfigObservation(StrictModel):
    smtp_client_authentication_disabled: bool | None = None
    allow_legacy_tls_clients: bool | None = None
    safety_net_hold_time: str = ""
    max_receive_size: str = ""
    max_send_size: str = ""


class ServiceHealthObservation(StrictModel):
    service: str
    status: str = ""


class ServiceIssueObservation(StrictModel):
    issue_ref: str
    service: str = ""
    status: str = ""
    classification: str = ""
    origin: str = ""
    feature: str = ""
    feature_group: str = ""
    start_date_time: str = ""
    end_date_time: str = ""
    last_modified_date_time: str = ""
