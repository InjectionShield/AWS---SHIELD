#!/usr/bin/python3

# Importing the AWS SDK
import boto3

# Creating a shield session
shield = boto3.client('shield')

#Creating Shield Advanced protection
response = shield.create_protection(
        Name = 'MyProtection',
        ResourceArn = 'arn:aws:s3:::examplebucket/*'
    )

#Enabling Shield Advanced protection
response = shield.enable_protection(
        ProtectionId = response['ProtectionId']
    )

#Generating the Attack Vectors
attack_vectors = shield.list_attack_vectors()

#Creating Mitigation Rules
for vector in attack_vectors['AttackVectors']:
    mitigation_rule = shield.create_subscription(
        AttackVectorType = vector['VectorType'],
        MaxRequestsPerSecond = 1000
    )

#Creating AWS WAF rules
#Getting the EC2 instance IP addresses
ec2 = boto3.client('ec2')
response = ec2.describe_instances()

#Creating the Rule for Instance IP
rule_name = 'InstanceIPsRule'
ip_addresses = []
for instance in response['Reservations']:
    ip_addresses.append(instance['Instances'][0]['PrivateIpAddress'])

#Creating the WAF rule for Instance IPs
rule = shield.create_subscription(
        RuleName = rule_name,
        RuleType = 'IP',
        RuleData = {
            'RuleString' : '{}{}{}'.format(''.join(ip_addresses), 'AND', 'NOT 127.0.0.1')
        }
    )

#Creating the Rule for Bots IP
rule_name = 'BotsIPsRule'

#Getting the IP addresses of bots
bot_ips = shield.list_attack_vectors()

#Creating the WAF rule for Bots IPs
rule = shield.create_subscription(
        RuleName = rule_name,
        RuleType = 'IP',
        RuleData = {
            'RuleString' : '{}{}{}'.format(''.join(bot_ips), 'AND', 'NOT 127.0.0.1')
        }
    )

#Creating the Rule for Custom IPs
rule_name = 'CustomIPsRule'
custom_ips = ['192.168.1.1','192.168.1.2','192.168.1.3','192.168.1.4']

#Creating the WAF rule for Custom IPs
rule = shield.create_subscription(
        RuleName = rule_name,
        RuleType = 'IP',
        RuleData = {
            'RuleString' : '{}{}{}'.format(''.join(custom_ips), 'AND', 'NOT 127.0.0.1')
        }
    )

#Creating the Rule for User Agent
rule_name = 'UserAgentRule'
user_agents = ['Mozilla/5.0','Googlebot/2.1']

#Creating the WAF rule for User Agent
rule = shield.create_subscription(
        RuleName = rule_name,
        RuleType = 'USER_AGENT',
        RuleData = {
            'RuleString' : '{}{}{}'.format(''.join(user_agents), 'AND', 'NOT 127.0.0.1')
        }
    )

#Creating the Rule for Country Code
rule_name = 'CountryCodeRule'
country_codes = ['US','UK','CA','AU','NZ']

#Creating the WAF rule for Country Code
rule = shield.create_subscription(
        RuleName = rule_name,
        RuleType = 'COUNTRY_CODE',
        RuleData = {
            'RuleString' : '{}{}{}'.format(''.join(country_codes), 'AND', 'NOT 127.0.0.1')
        }
    )

#Creating Access Control Policy
policy_name = 'MyAccessControlPolicy'

#Creating Access Control Policy
access_control_policy = shield.create_access_control_policy(
        PolicyName = policy_name,
        Rules = [
            {
                'Name': 'InstanceIPsRule',
                'Action': 'ALLOW'
            },
            {
                'Name': 'BotsIPsRule',
                'Action': 'BLOCK'
            },
            {
                'Name': 'CustomIPsRule',
                'Action': 'BLOCK'
            },
            {
                'Name': 'UserAgentRule',
                'Action': 'ALLOW'
            },
            {
                'Name': 'CountryCodeRule',
                'Action': 'ALLOW'
            }
        ]
    )

#Creating Web ACL
web_acl_name = 'MyWebACL'

#Creating Web ACL
web_acl = shield.create_web_acl(
        WebACLName = web_acl_name,
        Policy = access_control_policy['Policy']['PolicyId']
    )

#Attaching Web ACL to Shield Advanced
response = shield.attach_web_acl(
        ProtectionId = response['ProtectionId'],
        WebACLId = web_acl['WebACL']['WebACLId']
    )

#Listing the Shield Advanced protection
list_shield_advanced_protection = shield.list_protections()

#Printing the Shield Advanced Protection Details
print('The Shield Advanced Protection Details:')
print('-'*50)
for protection in list_shield_advanced_protection['Protections']:
    print('Protection ID: {}'.format(protection['ProtectionId']))
    print('Protection Name: {}'.format(protection['Name']))
    print('Resource ARN: {}'.format(protection['ResourceArn']))
    print('-'*50)
