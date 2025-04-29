# How I Set Up My Cybersecurity Portfolio

**1. Buy Your Domain**

Go to Namecheap.com, sign in or create an account.

In the search bar, enter your desired domain (e.g., vladcyber.it.com) and click Search.

When it’s available, click Add to Cart, then Checkout.

Leave WhoisGuard enabled for privacy, and complete payment.

In your dashboard, click Domain List, then Manage next to your new domain.

**2. Point the Domain to GitHub Pages**

In the Manage view, select the Advanced DNS tab.

Delete any default URL Redirect or parking CNAME records.

Click Add New Record four times and enter A records:

Host: @, Value: 185.199.108.153

Host: @, Value: 185.199.109.153

Host: @, Value: 185.199.110.153

Host: @, Value: 185.199.111.153

Click Add New Record, choose CNAME Record:

Host: www, Value: vignatovskiy1.github.io.

Save all changes (green check icon).

Wait ~15 minutes for DNS propagation.

In GitHub, go to your repo Settings → Pages, set Custom domain to vladcyber.it.com, check Enforce HTTPS, and save.

**3. Set Up Branded Email with Zoho Mail**

Visit mail.zoho.com, choose Business Email → Forever Free Plan, and sign up with “Use a domain I own.”

Enter your domain vladcyber.it.com, then copy the TXT verification value.

Back in Namecheap Advanced DNS, click Add New Record → TXT Record:

Host: @, Value: (paste Zoho’s TXT verification)

Click Add New Record → MX Record (repeat three times):

Host: @, Value: mx.zoho.com, Priority: 10

Host: @, Value: mx2.zoho.com, Priority: 20

Host: @, Value: mx3.zoho.com, Priority: 50

Click Add New Record → TXT Record for SPF:

Host: @, Value: v=spf1 include:zoho.com ~all

Wait ~20 minutes, then in Zoho click Verify all records.

In Zoho Admin, create a user mailbox (e.g., contact@vladcyber.it.com).

**4. Build and Deploy Your Homepage**

Navigate to your GitHub repo vignatovskiy1 and select Add file → Create new file.

Name the file index.html.

Paste a complete HTML document 

Scroll down and Commit new file to the main branch.

Wait a minute for GitHub Pages to build, then go to Settings → Pages in your repo, ensure the branch is set to main and your custom domain is applied. Enable Enforce HTTPS, and save.
