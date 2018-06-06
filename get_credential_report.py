import boto3
import botocore
import StringIO
import csv
import datetime


def lambda_handler(context,event):

    session = role_arn_to_session(
            #RoleArn='arn:aws:iam::******:role/DevIamAuditRole',
            RoleArn='arn:aws:iam::******:role/SandpitIamAuditRole',
            RoleSessionName='iam_audit_session')
    iam_client = session.client('iam')
    sns= boto3.client('sns')
    sns_report = []
    credReport=generate_cred_report(iam_client)
    accessKeyCount=0
    userCount=0
    print ('##############################################################################################################')
    print (' | ' + 'ACCESS KEY NAME' + ' | ' + 'CREATED ON' + ' | ' 'LAST USED SERVICE' + ' | ' + 'IS KEY ACTIVE' + ' | '+ 'MFA ENABLED') 
    print ('##############################################################################################################')  
    sns_report.append ('##############################################################################################################')
    sns_report.append (' | ' + 'ACCESS KEY NAME' + ' | ' + 'CREATED ON' + ' | ' 'LAST USED SERVICE' + ' | ' + 'IS KEY ACTIVE' + ' | '+ 'MFA ENABLED') 
    sns_report.append ('##############################################################################################################')  
    
    for row in credReport:
        if row['password_enabled'] == "false":
            creationDate= row['user_creation_time']
            accessKeyCount=accessKeyCount+1
            print (' | ' + row['user'] + ' | ' +  creationDate[0:10]  + ' | ' +  row['access_key_1_last_used_service'] + ' | ' + row['access_key_1_active']  + ' | ' + row['mfa_active'] )
            sns_report.append (' | ' + row['user'] + ' | ' +  creationDate[0:10]  + ' | ' +  row['access_key_1_last_used_service'] + ' | ' + row['access_key_1_active']  + ' | ' + row['mfa_active'] )

    print ("\n===================================" )
    print ('Total Number Of Access Keys: ' + str(accessKeyCount))
    print ("===================================" )
    sns_report.append ("\n===================================" )
    sns_report.append ('Total Number Of Access Keys: ' + str(accessKeyCount))
    sns_report.append ("===================================" )
    
    userCount=0
    print ('##############################################################################################################')
    print (' | ' + 'USER NAME' + ' | ' + 'CREATED ON' + ' | ' 'LAST USED SERVICE' + ' | ' + 'IS USER ACTIVE' + ' | '+ 'MFA ENABLED') 
    print ('##############################################################################################################')  

    
    for row in credReport:
        if row['password_enabled'] == "true":
            creationDate= row['user_creation_time']
            userCount=userCount+1
            print (' | ' + row['user'] + ' | ' +  creationDate[0:10]  + ' | ' +  row['access_key_1_last_used_service'] + ' | ' + row['access_key_1_active']  + ' | ' + row['mfa_active'] )
    print ("\n===================================" )
    print ('Total Number Of Console Users: ' + str(userCount)  )
    print ("===================================" )    
 
    response = sns.publish(
    TopicArn='arn:aws:sns:eu-west-1:*******:mfa_lacking',
    Message= '\n'.join(sns_report),
    Subject='SandPit IAM User Details',
)   
    
def generate_cred_report(iam_client):
    credReport = None
    while credReport == None:
        try:
            credReport = iam_client.get_credential_report()
        except botocore.exceptions.ClientError as e:
            if 'ReportNotPresent' in e.message:
                iam_client.generate_credential_report()
            else:
                raise e
            time.sleep(5)
    document = StringIO.StringIO(credReport['Content'])
    reader = csv.DictReader(document)
    report_rows = []
    for row in reader:
        report_rows.append(row)
    
    return report_rows  
    
def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

