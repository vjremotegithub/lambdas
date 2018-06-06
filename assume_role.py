

import boto3
import json

def lambda_handler(context,event):

    session = role_arn_to_session(
            RoleArn='arn:aws:iam::*****:role/IamAuditRole',
            RoleSessionName='iam_audit_session')
    client = session.client('iam')
    #client= boto3.client('iam')
    #sns= boto3.client('sns')
    users = client.list_users()
    user_list = []
    
    print ('##############################################################################################################')
    print (' | ' + 'USERNAME' + ' | ' + 'USER CREATED ON' + ' | ' 'USER LAST LOGGED IN DATE' + ' | '+ 'IS MFA CONFIGURED')
    print ('##############################################################################################################')  
    userDetailsStringHeader= 'USERNAME' + ' | ' + 'USER POLICIES' + ' | ' 'USER GROUPS' + ' | '+ 'IS MFA CONFIGURED'
    
    user_list.append('##############################################################################################################'+'\n')
    user_list.append(userDetailsStringHeader+'\n')
    user_list.append('##############################################################################################################'+'\n')
    for key in users['Users']:
        userName=key['UserName']
        userDetails =  client.get_user(UserName=key['UserName'])
        try:
            PasswordLastUsed=userDetails['User']['PasswordLastUsed']
            PasswordLastUsed='{:%d, %b %Y}'.format(userDetails['User']['PasswordLastUsed'])
            userType='CONSOLE USER'
        except Exception, e:
            PasswordLastUsed='Never Logged In'
            userType= 'NON CONSOLE USER'

        print ' | ' + userDetails['User']['UserName'] + ' | ' +  '{:%d, %b %Y}'.format(userDetails['User']['CreateDate']) + ' | ' +  str(PasswordLastUsed) + ' | ' + userType
        #user_list.append(userDetails)
    
    #print user_list

def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

