
import boto3
def lambda_handler(context,event):
   
    client                  = boto3.client('iam')
    sns                     = boto3.client('sns')
    response                = client.list_users()
    userVirtualMfa          = client.list_virtual_mfa_devices()
    mfaNotEnabled           = []
    virtualEnabled          = []
    physicalString          = ''
    
    # loop through virtual mfa to find users that actually have it
    for virtual in userVirtualMfa['VirtualMFADevices']:
        virtualEnabled.append(virtual['User']['UserName'])
           
    # loop through users to find physical MFA
    for user in response['Users']:
        userMfa  = client.list_mfa_devices(UserName=user['UserName'])
        
        if len(userMfa['MFADevices']) == 0:
            if user['UserName'] not in virtualEnabled:
                mfaNotEnabled.append(user['UserName']) 
    
    
    if len(mfaNotEnabled) > 0:
        physicalString = 'Physical & Virtual MFA is not enabled for the following users: \n\n=========================\n\n' +
         '\n'.join(mfaNotEnabled) +'\n\n========================='
    else:
        physicalString = 'All Users have Physical and Virtual MFA enabled'
    
    response = sns.publish(
        TopicArn='arn:aws:sns:eu-west-1:989140231452:mfa_lacking',
        Message= physicalString,
        Subject='Enable MFA',
    )
    
    return mfaNotEnabled