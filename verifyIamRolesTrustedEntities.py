import boto3
import datetime
import sys
import os

def lambda_handler(context,event):
  
    listOfDefraTrustedAccounts=[]
    totalAccounts=int(os.environ['TrustedAccountsCount'])
    for accountNumber  in range(1, totalAccounts+1):
      print (os.environ['TrustedAccount'+str(accountNumber)])
      listOfDefraTrustedAccounts.append(os.environ['TrustedAccount'+str(accountNumber)])
    sys.exit()
   
    session = role_arn_to_session(
            RoleArn='arn:aws:iam::******:role/DevIamAuditRole',
            #RoleArn='arn:aws:iam::*******:role/SandpitIamAuditRole',
            RoleSessionName='iam_audit_session')
    iam_client = session.client('iam')
    roles=iam_client.list_roles()
    roleList = roles['Roles']
    for key in roleList:
        print('++++++++++++++++++++++++++')
        print key['RoleName']
        #print key['Arn']
        print('++++++++++++++++++++++++++')
        try:
            
            assumeRolePolicyPrincipal= key['AssumeRolePolicyDocument']['Statement'][0]['Principal']['AWS']
            print assumeRolePolicyPrincipal
            if any("540975*****" in s for s in assumeRolePolicyPrincipal):
                print ('MATCHES LIST')
            elif '*****735942' in assumeRolePolicyPrincipal:
                print ('MATCHES STRING')
                
        except Exception, e:
            print ''

 

def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

