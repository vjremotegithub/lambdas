

import boto3
import json

def lambda_handler(context,event):
   
    client                  = boto3.client('iam')
    sns                     = boto3.client('sns')
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
        allUsers = []

    
        userName=key['UserName']
        userDetails =  client.get_user(UserName=key['UserName'])
        
        try:
            PasswordLastUsed=userDetails['User']['PasswordLastUsed']
            PasswordLastUsed='{:%d, %b %Y}'.format(userDetails['User']['PasswordLastUsed'])
        except Exception, e:
            PasswordLastUsed='Never Logged In'
            
        '''
        if str(userDetails['User']['PasswordLastUsed'])=='':
            PasswordLastUsed='Never Logged In'
        else:
            PasswordLastUsed = str(userDetails['User']['PasswordLastUsed'])
        print userDetails['User']['UserName'] + '  ' +  str(userDetails['User']['CreateDate']) + '  ' +  PasswordLastUsed
        
        '''
        print ' | ' + userDetails['User']['UserName'] + ' | ' +  '{:%d, %b %Y}'.format(userDetails['User']['CreateDate']) + ' | ' +  str(PasswordLastUsed)