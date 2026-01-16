# AD User Creation Script with Randomized Passwords
# This script creates 100 users in a structured AD format

# STEP 1: Import the Active Directory PowerShell module
# This gives us access to commands like New-ADUser, Get-ADUser, etc.
Import-Module ActiveDirectory

# STEP 2: Set up configuration variables
# $Domain defines your Active Directory domain structure
# YOU NEED TO CHANGE THIS to match your actual domain (e.g., DC=contoso,DC=local)
$Domain = "DC=yourdomain,DC=com"

# $BaseOU is where all our users will live - we're putting them in a "Users" OU
$BaseOU = "OU=Users,$Domain"

# STEP 3: Define the organizational structure
# This array contains each department with:
#   - Name: Department name
#   - OU: Full path where users will be created
#   - Count: How many users to create in this department
# Total adds up to 100 users (15+20+15+10+15+25=100)
$Departments = @(
    @{Name="IT"; OU="OU=IT,$BaseOU"; Count=15},
    @{Name="Sales"; OU="OU=Sales,$BaseOU"; Count=20},
    @{Name="Marketing"; OU="OU=Marketing,$BaseOU"; Count=15},
    @{Name="HR"; OU="OU=HR,$BaseOU"; Count=10},
    @{Name="Finance"; OU="OU=Finance,$BaseOU"; Count=15},
    @{Name="Operations"; OU="OU=Operations,$BaseOU"; Count=25}
)

# STEP 4: Create arrays of realistic names
# These will be randomly selected to create user accounts
# We have 40 first names and 30 last names for variety
$FirstNames = @("James","John","Robert","Michael","William","David","Richard","Joseph","Thomas","Charles",
                "Mary","Patricia","Jennifer","Linda","Barbara","Elizabeth","Susan","Jessica","Sarah","Karen",
                "Daniel","Matthew","Anthony","Mark","Donald","Steven","Paul","Andrew","Joshua","Kenneth",
                "Nancy","Lisa","Betty","Margaret","Sandra","Ashley","Kimberly","Emily","Donna","Michelle")

$LastNames = @("Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez",
               "Hernandez","Lopez","Gonzalez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson","Martin",
               "Lee","Walker","Hall","Allen","Young","King","Wright","Scott","Torres","Nguyen")

# Function to generate random password
function Generate-RandomPassword {
    param([int]$Length = 16)
    
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lower = "abcdefghijklmnopqrstuvwxyz"
    $numbers = "0123456789"
    $special = "!@#$%^&*"
    
    $allChars = $upper + $lower + $numbers + $special
    
    # Ensure at least one of each type
    $pwd = @()
    $pwd += $upper[(Get-Random -Maximum $upper.Length)]
    $pwd += $lower[(Get-Random -Maximum $lower.Length)]
    $pwd += $numbers[(Get-Random -Maximum $numbers.Length)]
    $pwd += $special[(Get-Random -Maximum $special.Length)]
    
    # Fill the rest randomly
    for ($i = 0; $i -lt ($Length - 4); $i++) {
        $pwd += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    # Shuffle the password
    return -join ($pwd | Get-Random -Count $pwd.Count)
}

# Function to create OUs if they don't exist
function Create-OUStructure {
    param([string]$OUPath)
    
    try {
        Get-ADOrganizationalUnit -Identity $OUPath -ErrorAction Stop | Out-Null
        Write-Host "OU already exists: $OUPath" -ForegroundColor Yellow
    }
    catch {
        $ouName = ($OUPath -split ',')[0] -replace 'OU=',''
        $parentPath = ($OUPath -split ',',2)[1]
        
        New-ADOrganizationalUnit -Name $ouName -Path $parentPath
        Write-Host "Created OU: $OUPath" -ForegroundColor Green
    }
}

# Create base Users OU
Write-Host "`n=== Creating OU Structure ===" -ForegroundColor Cyan
try {
    Create-OUStructure -OUPath $BaseOU
}
catch {
    Write-Host "Error creating base OU: $_" -ForegroundColor Red
}

# Create department OUs
foreach ($dept in $Departments) {
    try {
        Create-OUStructure -OUPath $dept.OU
    }
    catch {
        Write-Host "Error creating OU for $($dept.Name): $_" -ForegroundColor Red
    }
}

# Create CSV for password documentation
$csvPath = ".\AD_Users_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$userList = @()

Write-Host "`n=== Creating Users ===" -ForegroundColor Cyan

$userCounter = 1

foreach ($dept in $Departments) {
    Write-Host "`nCreating $($dept.Count) users in $($dept.Name) department..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le $dept.Count; $i++) {
        $firstName = $FirstNames | Get-Random
        $lastName = $LastNames | Get-Random
        $username = "$($firstName.ToLower()).$($lastName.ToLower())$userCounter"
        $displayName = "$firstName $lastName"
        $email = "$username@yourdomain.com"
        $password = Generate-RandomPassword
        
        try {
            # Check if user already exists
            if (Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue) {
                Write-Host "  User already exists: $username" -ForegroundColor Yellow
                $userCounter++
                continue
            }
            
            # Create the user
            New-ADUser `
                -SamAccountName $username `
                -UserPrincipalName $email `
                -Name $displayName `
                -GivenName $firstName `
                -Surname $lastName `
                -DisplayName $displayName `
                -EmailAddress $email `
                -Department $dept.Name `
                -Title "$($dept.Name) Specialist" `
                -Path $dept.OU `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                -Enabled $true `
                -ChangePasswordAtLogon $true `
                -PasswordNeverExpires $false
            
            Write-Host "  Created: $username" -ForegroundColor Green
            
            # Add to CSV list
            $userList += [PSCustomObject]@{
                Username = $username
                DisplayName = $displayName
                Email = $email
                Department = $dept.Name
                Password = $password
                OU = $dept.OU
            }
            
        }
        catch {
            Write-Host "  Error creating $username : $_" -ForegroundColor Red
        }
        
        $userCounter++
    }
}

# Create a formatted text file with usernames and passwords
$txtPath = ".\users for company.txt"
$txtContent = @()
$txtContent += "=" * 80
$txtContent += "ACTIVE DIRECTORY USER CREDENTIALS"
$txtContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$txtContent += "=" * 80
$txtContent += ""

foreach ($dept in $Departments) {
    $deptUsers = $userList | Where-Object { $_.Department -eq $dept.Name }
    
    if ($deptUsers.Count -gt 0) {
        $txtContent += ""
        $txtContent += "-" * 80
        $txtContent += "DEPARTMENT: $($dept.Name.ToUpper())"
        $txtContent += "-" * 80
        
        foreach ($user in $deptUsers) {
            $txtContent += ""
            $txtContent += "Username: $($user.Username)"
            $txtContent += "Password: $($user.Password)"
            $txtContent += "Display Name: $($user.DisplayName)"
            $txtContent += "Email: $($user.Email)"
        }
    }
}

$txtContent += ""
$txtContent += "=" * 80
$txtContent += "TOTAL USERS CREATED: $($userList.Count)"
$txtContent += "=" * 80
$txtContent += ""
$txtContent += "SECURITY NOTICE:"
$txtContent += "- Store this file in a secure location"
$txtContent += "- Delete this file after distributing credentials"
$txtContent += "- Users must change passwords on first login"
$txtContent += "=" * 80

# Write to text file
$txtContent | Out-File -FilePath $txtPath -Encoding UTF8

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total users created: $($userList.Count)" -ForegroundColor Green
Write-Host "Credentials saved to: $txtPath" -ForegroundColor Green
Write-Host "`nIMPORTANT: Store this file securely and delete it after distributing passwords!" -ForegroundColor Yellow