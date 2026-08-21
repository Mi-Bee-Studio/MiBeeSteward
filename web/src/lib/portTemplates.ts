// Port whitelist templates for scan tasks and quick scans (#275).
//
// Data-driven presets: one-click application to the port editor. Kept as a TS
// module (not configs/ YAML) because the SPA is embedded in the binary and
// configs/ is not served to the browser; adding a template is a one-entry
// change here plus the two locale files.

import { m } from '$lib/i18n-paraglide';

export interface PortTemplate {
	/** localized label (a function so the active locale renders live) */
	label: () => string;
	/** port spec, same syntax as pipeline_config.port_scan.ports */
	ports: string;
}

export const portTemplates: PortTemplate[] = [
	{
		label: () => m['scanner.templates.web'](),
		ports: '22,80,443,8080,8443'
	},
	{
		label: () => m['scanner.templates.cctv'](),
		ports: '80,443,554,8554,5544,8899,8000,8080,37777'
	},
	{
		label: () => m['scanner.templates.database'](),
		ports: '1433,1521,3306,5432,6379,8529,9200,11211,27017'
	},
	{
		label: () => m['scanner.templates.network'](),
		ports: '22,23,80,443,161,829,830,5000,8080,8443'
	},
	{
		label: () => m['scanner.templates.monitoring'](),
		ports: '9090,9100,9104,9113,9121,9187,9200,8125,19999'
	},
	{
		// A curated ~100-port set: the engine's fingerprint list plus the most
		// commonly open service ports (web/admin/cameras/storage/remote access).
		label: () => m['scanner.templates.top100'](),
		ports: [
			'21,22,23,25,53', // access/dns/mail
			'80,81,88,110,123,135,139', // web/netbios/ntp
			'143,161,389,443,445,465', // imap/snmp/ldap/smb
			'500,514,515,543,544,554,587', // isakmp/syslog/lpd/rtsp
			'631,636,646,829,830,873,990', // ipp/ldaps/xoap/netconf/rsync
			'992,993,995,1080,1099,1433', // tls shells/proxy/rdp-db
			'1521,1723,1883,2049,2082,2083', // oracle/pptp/mqtt/nfs/cpanel
			'2100,2181,2375,2376,3000,3128', // zabbix/es registry/grafana/squid
			'3260,3306,3389,3690,4444,4848', // iscsi/mysql/rdp/svn/jenkins
			'5000,5001,5432,5544,5672,5900', // synology/pg/rtsp-alt/amqp/vnc
			'5984,5985,5986,6379,6443,6667', // couchdb/winrm/k8s/redis/irc
			'7777,8000,8008,8009,8010,8069', // alt-web/hadoop
			'8080,8081,8086,8088,8089,8125', // proxies/influx
			'8161,8200,8443,8500,8529,8554', // activemq/consul/etcd/rtsp-tls
			'8686,8728,8767,8844,8899,9000', // jenkins/tornado/alt-tls/minio
			'9001,9042,9080,9090,9092,9100', // cassandra/prometheus/node
			'9160,9200,9300,9418,9443,9527', // cassandra/es/mtls
			'9999,10000,10250,11211,15672,18083', // nbox/webmin/hbase-edge
			'19000,20000,27017,32400,37777,49152', // storage/nvr
			'50050,55555,61613,61616' // hadoop/activemq-alt
		].join(',')
	}
];
