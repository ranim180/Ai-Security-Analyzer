from django.http import HttpResponse, JsonResponse
from .middleware import is_malicious
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from .models import BankAccount, Transaction, UserProfile
import sqlite3
import json
import time
import requests
from django.shortcuts import render, redirect

#/////////////////////////////////////////////////////////////////////////////////////////
# home page html
def home(request):
    return render(request, 'banking_env/home.html')
#vulnerability 1 :SQL Injection in the login form 

def vulnerable_login(request):
    if request.method=='POST':
        username=request.POST.get('username')
        password=request.POST.get('password')

        # VULNERABLE: Direct SQL concatenation
        conn=sqlite3.connect('db.sqlite3')
        cursor =conn.cursor()
        cursor.execute(f"SELECT id,username FROM auth_user WHERE username='{username}' AND password='{password}'")
        user_data=cursor.fetchone()
        conn.close()
        if user_data:
            user=User.objects.get(id=user_data[0])
            login(request,user)
            return redirect('/dashboard')
        else:
            return HttpResponse("Login failed ! <a href='/login'>Try again </a>")
    
    # ADD THIS: Return the login form for GET requests
    return HttpResponse('''
    <h2> Bank Login (SQL Injection Vulnerable)</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit">Login</button>
    </form>
    <p><strong>Test payload:</strong> <code>' OR '1'='1' -- </code></p>
    ''')


#vulnerability 2 :XSS in the login form 
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('/login')
    search = request.GET.get('search','') 
    #VULNERABLE :REFLECTED XSS
    return HttpResponse(f''' 
    <h2>Banking Dashboard</h2>
    <p>Welcome, {request.user.username}!</p>
    
    <form>
        <input type="text" name="search" value="{search}" placeholder="Search transactions">
        <button type="submit">Search</button>
    </form>
    
    <p>Search results for: {search}</p>
    
    <div>
        <h3>Quick Actions:</h3>
        <a href="/transfer">Transfer Money</a> | 
        <a href="/account">View Account</a>
    </div>
     ''')


#vulnerability 3 : CSRF in Money Transfer
def transfer_money(request):
    if not request.user.is_authenticated:
        return redirect('/login')
    if request.method=='POST':
        to_account=request.POST.get('to_account')
        amount=request.POST.get('amount')
        #Vunlerable :No CSRF protection w no authorization checks
        try:
            from_account =BankAccount.objects.get(user=request.user)
            to_account_obj=BankAccount.objects.get(account_number=to_account)
            #logic mtaa transfer mtaa lfous
            if from_account.balance>=float(amount):
                from_account.balance -=float(amount)
                to_account_obj.balance +=float(amount)
                from_account.save()
                to_account_obj.save()
                # Create transaction record
                Transaction.objects.create(
                    from_account=from_account,
                    to_account=to_account_obj,
                    amount=amount,
                    transaction_type='TRANSFER',
                    description=f'Transfer to {to_account}'
                )

                return HttpResponse(f'''
                <h3>transfer Successful!</h3>
                <p>Transferred ${amount} to account {to_account}</p>
                <a href="/transfer">Make another transfer</a>
                ''')
            else:
                return HttpResponse("Insufficient Funds!")


        except BankAccount.DoesNotExist:
            return HttpResponse("Account not found!")
    
    return HttpResponse('''
    <h2> Transfer Money (CSRF Vulnerable)</h2>
    <form method="POST">
        <!-- NO CSRF TOKEN - This is vulnerable! -->
        To Account: <input type="text" name="to_account" required><br>
        Amount: $<input type="number" name="amount" step="0.01" required><br>
        <button type="submit">Transfer Money</button>
    </form>
    
    <h3>CSRF Attack Demo:</h3>
    <textarea rows="4" cols="50">
    <!-- Save this as attack.html and open it -->
    <html>
    <body onload="document.forms[0].submit()">
        <form action="http://localhost:8000/transfer" method="POST">
            <input type="hidden" name="to_account" value="ATTACKER_ACCOUNT">
            <input type="hidden" name="amount" value="1000">
        </form>
    </body>
    </html>
    </textarea>
    ''')


#vulnerability 4 :IDOR (Insecure Direct Object Reference)
def account_info(request):
    if not request.user.is_authenticated:
        return redirect("/login")
    account_id=request.GET.get('account_id','')
    # vulnerability bech tkoun lehne khater user ynajem ychouf ay account ekher 
    if account_id:
        try:
            account=BankAccount.objects.get(id=account_id)
            return HttpResponse(f'''
            <h2>Account Information</h2>
            <p><strong>Account Owner:</strong> {account.user.username}</p>
            <p><strong>Account Number:</strong> {account.account_number}</p>
            <p><strong>Balance:</strong> ${account.balance}</p>
            <p><em>IDOR Vulnerability: You can view any account by changing account_id parameter</em></p>
            <a href="/account">Back to my account</a>
            ''')
        except BankAccount.DoesNotExist :
            return HttpResponse("Account not found")
    
    # Show current user's account when no account_id provided
    try:
        account = BankAccount.objects.get(user=request.user)
        return HttpResponse(f'''
        <h2> My Account</h2>
        <p><strong>Account Number:</strong> {account.account_number}</p>
        <p><strong>Balance:</strong> ${account.balance}</p>
        
        <h3>View Other Accounts (IDOR Test):</h3>
        <form>
            Account ID: <input type="number" name="account_id" placeholder="1, 2, 3...">
            <button type="submit">View Account</button>
        </form>
        ''')
    except BankAccount.DoesNotExist:
        return HttpResponse("No account found")


#vulnerability 5 :SSRF (Server-Side Request Forgery)
def api_fetch_external_data(request):
    # Bank needs to fetch external financial data, but implementation is insecure
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'})
    url=request.GET.get('url','')
    if url:
        try:
            response=requests.get(url,timeout=5)
            # Simulate some financial data processing
            time.sleep(0.5)  # Add small delay to make it seem like processing
            return JsonResponse({
                'status': 'success',
                'url': url,
                'content_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text,
                'content_length': len(response.text),
                'status_code': response.status_code
            })
            
        except Exception as e:
            return JsonResponse({'error': f'Failed to fetch URL: {str(e)}'})
    return JsonResponse({'error': 'URL parameter required'})