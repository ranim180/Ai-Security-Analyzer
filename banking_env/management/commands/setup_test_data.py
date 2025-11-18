import os
import sys
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from banking_env.models import BankAccount, UserProfile


class Command(BaseCommand):
    help="create test users and their bank accounts for vulnerability testing"
    def handle(self,*args,**options):
        #Create test users
        test_users = [
            {'username': 'ranim', 'password': 'password123', 'balance': 5000},
            {'username': 'ghada', 'password': 'password123', 'balance': 3000},
            {'username': 'amina', 'password': 'password123', 'balance': 1000},  # Attacker
        ]
        for user_data in test_users:
            user,created=User.objects.get_or_create(username=user_data['username'])
            if created:
                user.set_password(user_data['password'])
                user.save()
                #Create bank account 
                account =BankAccount.objects.create(
                    user=user,
                    account_number =f"ACC{user.id:06d}", #ACC000001-ACC000002 -ACC000003 c est comme ca le formattage de lid 
                    balance=user_data['balance']
                )
                # Create user profile 
                UserProfile.objects.create(user=user)
                self.stdout.write(self.style.SUCCESS(f'Created user {user.username} with account {account.account_number}'))
                
         
        
         