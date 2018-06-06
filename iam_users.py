

import boto3

def lambda_handler(context,event):
   
    client                  = boto3.client('iam')
    sns                     = boto3.client('sns')
    users = client.list_users()
    user_list = []
    
    print '##############################################################################################################'
    print 'USERNAME' + ' | ' + 'USER POLICIES' + ' | ' 'USER GROUPS' + ' | '+ 'IS MFA CONFIGURED'
    print '##############################################################################################################'  
    userDetailsStringHeader= 'USERNAME' + ' | ' + 'USER POLICIES' + ' | ' 'USER GROUPS' + ' | '+ 'IS MFA CONFIGURED'
    
    user_list.append('##############################################################################################################'+'\n')
    user_list.append(userDetailsStringHeader+'\n')
    user_list.append('##############################################################################################################'+'\n')
    for key in users['Users']:
        result = []
        Policies = []
        Groups=[]
    
        userName=key['UserName']
        List_of_Policies =  client.list_user_policies(UserName=key['UserName'])
    
        policyNames = List_of_Policies['PolicyNames']
    
        List_of_Groups =  client.list_groups_for_user(UserName=key['UserName'])
    
        for Group in List_of_Groups['Groups']:
            Groups.append(Group['GroupName'])
        groups = Groups
    
        List_of_MFA_Devices = client.list_mfa_devices(UserName=key['UserName'])
    
        if not len(List_of_MFA_Devices['MFADevices']):
            isMFADeviceConfigured='False'   
        else:
            isMFADeviceConfigured='True'    

        #print str(userName) + ' | ' + str(policyNames) + ' | ' + str(groups) + ' | ' + isMFADeviceConfigured
        userDetailsString= str(userName) + ' | ' + str(policyNames) + ' | ' + str(groups) + ' | ' + isMFADeviceConfigured +'\n'
        user_list.append(userDetailsString)
  
    user_list.append('##############################################################################################################'+'\n')
    print  '\n'.join(user_list)    
    response = sns.publish(
    TopicArn='arn:aws:sns:eu-west-1:******:mfa_lacking',
    Message= '\n'.join(user_list),
    Subject='IAM User Details',
)