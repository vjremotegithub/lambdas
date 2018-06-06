
import boto3
from datetime import datetime
import os
import sys
import time

user_list = []
global noUserFlag

def lambda_handler(context,event):

            roleList=[]
            roleList.append(os.environ['Role1'])
            roleList.append (os.environ['Role2'])
            roleList.append (os.environ['Role3'])
            noUserFlag=0
            for role in roleList:
                noUserFlag=dailyChecker(role,noUserFlag)
            if     noUserFlag==1:
                emailIamAuditReport(user_list)
            #sns_report.clear() # Python 3
            del user_list[:]

def dailyChecker(roleName,noUserFlag):
                
    session = role_arn_to_session(
            RoleArn=roleName,
            RoleSessionName='iam_audit_session')
    client = session.client('iam')
    #client= boto3.client('iam')
    users = client.list_users()
    if 'Dev' in roleName:
        awsAccountName="DEVELOPMENT"
    elif 'Qa' in roleName:
        awsAccountName="QA"
    elif 'Sandpit' in roleName:
        awsAccountName="SANDPIT"
    print('\n'+'#####################################################')
    print ('AWS ACCOUNT NAME: ' + awsAccountName) 
    print('#####################################################')
    user_list.append ('\n'+'#####################################################')
    user_list.append ('AWS ACCOUNT NAME: ' + awsAccountName) 
    user_list.append ('#####################################################')
    print ('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print (' | '+ 'USERNAME'  + ' | '+ 'USER CREATED ON'  + ' | ' + 'USER POLICIES' + ' | ' 'USER GROUPS' + ' | '+ 'IS MFA ENABLED')
    print ('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++') 
    userDetailsStringHeader= ' | '+ 'USERNAME'  + ' | '+'USER CREATED ON'  + ' | ' + 'USER POLICIES' + ' | ' 'USER GROUPS' + ' | '+ 'IS MFA ENABLED'
    
    user_list.append('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    user_list.append(userDetailsStringHeader)
    user_list.append('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    for key in users['Users']:
        Policies = []
        Groups=[]
        userName=key['UserName']
        userDetails =  client.get_user(UserName=key['UserName'])
        try:
            PasswordLastUsed=userDetails['User']['PasswordLastUsed']
            PasswordLastUsed='{:%d, %b %Y}'.format(userDetails['User']['PasswordLastUsed'])
            #userType='CONSOLE USER'
        except Exception, e:
            PasswordLastUsed='Never Logged In'
            #userType= 'NON CONSOLE USER'
        listOfPolicies =  client.list_user_policies(UserName=key['UserName'])
        policyNames = listOfPolicies['PolicyNames']
    
        listOfGroups =  client.list_groups_for_user(UserName=key['UserName'])
        for Group in listOfGroups['Groups']:
            Groups.append(Group['GroupName'])
        groups = Groups
 
        listOfMFADevices = client.list_mfa_devices(UserName=key['UserName'])
        if not len(listOfMFADevices['MFADevices']):
            isMFADeviceConfigured='False'   
        else:
            isMFADeviceConfigured='True'           

        userCreatedDate= "{:%d.%m.%Y}".format(userDetails['User']['CreateDate'])
        todaysDate= "{:%d.%m.%Y}".format(datetime.now())
        #print userCreatedDate
        #print todaysDate
        userDetailsString=  ' | ' + userDetails['User']['UserName']  + ' | ' +  '{:%d, %b %Y}'.format(userDetails['User']['CreateDate']) +  ' | ' + str(policyNames) + ' | ' + str(groups) + ' | ' + isMFADeviceConfigured 
        if userCreatedDate == todaysDate:
            print (userDetailsString)
            print ('##############################################################################################################')  
            user_list.append( userDetailsString)

            noUserFlag = 1
    
    if noUserFlag!=1:
        print (' | ' + 'NO USERS WERE CREATED ON: ' + todaysDate + ' | ')
        user_list.append(' | ' + 'NO USERS WERE CREATED ON: ' + todaysDate +' | ' )
 
    return noUserFlag

    
def emailIamAuditReport(sns_report):
    sns= boto3.client('sns')
    response = sns.publish(
    TopicArn='arn:aws:sns:eu-west-1:*******:IamCrossAccountUsersAuditTopic',
    Message= '\n'.join(sns_report),
    Subject="LIST OF IAM USERS CREATED ON: " + "{:%d.%m.%Y}".format(datetime.now()),
)   
        
def role_arn_to_session(**args):
    client = boto3.client('sts')
    response = client.assume_role(**args)
    print response
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

