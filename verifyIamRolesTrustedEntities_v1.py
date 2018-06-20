import boto3
import datetime
import sys
import os

def lambda_handler(context,event):
  
     # Get the service resource.
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('AWS_ACCOUNTS')
    response = table.scan()
    roleList = response['Items']
    for role  in roleList:
         print ('#########################################################################')
         print ('AWS ACCOUNT NAME: ' + role['Account_Name'])
         print ('#########################################################################')
         checkAwsAccountForTrustedEntities(role['Assumed_Role'], role['Account_Name'],role['Account_id'],dynamodb)
         #sys.exit()
         
def checkAwsAccountForTrustedEntities(roleName,awsAccountName, awsAccountId,dynamodb):
    session = role_arn_to_session(
            RoleArn= roleName,
            RoleSessionName='iam_audit_session')
    iam_client = session.client('iam')   
    roles=iam_client.list_roles()
    roleList = roles['Roles']
    for key in roleList:
        #print key['RoleName']
        #print key['Arn']
        try:
            assumeRolePolicyPrincipal= key['AssumeRolePolicyDocument']['Statement'][0]['Principal']['AWS']
        except Exception, e:
                #print (e.message)
                continue
        table = dynamodb.Table('TRUSTED_ACCOUNTS')
        response = table.scan()
        accountsList = response['Items']
        #print ('AssumedRolePolicyPrincipal: ' + str(assumeRolePolicyPrincipal))
        matchFound='No'
        for account  in accountsList:
            if str(account['AwsAccountNumber']) in str(assumeRolePolicyPrincipal):
                    #print ('AssumedRolePolicyPrincipal: ' + str(assumeRolePolicyPrincipal))
                    #print ('Matching Account:' + str(account['AwsAccountNumber']))
                    matchFound='Yes'

        if matchFound=='No':
            #print('BREACH: ' + assumeRolePolicyPrincipal )
            print ('BREACH IN ROLE: ' + key['RoleName'])
            print('UNKNOWN AWS ACCOUNT IN ABOVE ROLE: '+ str(assumeRolePolicyPrincipal)+'\n' )


def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

