# Test that a box's fail2ban setting are working
# correctly by attempting a bunch of failed logins.
######################################################################

import sys, os, time, functools

# parse command line

if len(sys.argv) < 2:
	print("Usage: tests/fail2ban.py user@hostname")
	sys.exit(1)

ssh_user, hostname = sys.argv[1].split("@", 1)

# define some test types

def smtp_test():
	import smtplib
	server = smtplib.SMTP(hostname, 587)
	server.starttls()
	server.ehlo_or_helo_if_needed()
	try:
		server.login("fakeuser", "fakepassword")
		raise Exception("authentication didn't fail")
	except smtplib.SMTPAuthenticationError:
		# athentication should fail
		pass
	server.quit()

def imap_test():
	import imaplib
	M = imaplib.IMAP4_SSL(hostname)
	try:
		M.login("fakeuser", "fakepassword")
		raise Exception("authentication didn't fail")
	except imaplib.IMAP4.error:
		# authentication should fail
		pass
	M.logout() # shuts down connection, has nothing to do with login()

def http_test(url, expected_status, postdata=None, qsargs=None, auth=None):
	import urllib.parse
	import requests
	from requests.auth import HTTPBasicAuth

	# form request
	url = urllib.parse.urljoin("https://" + hostname, url)
	if qsargs: url += "?" + urllib.parse.urlencode(qsargs)
	urlopen = requests.get if not postdata else requests.post

	# issue request
	r = urlopen(
		url,
		auth=HTTPBasicAuth(*auth) if auth else None,
		data=postdata,
		headers={'User-Agent': 'Mail-in-a-Box fail2ban tester'},
		timeout=4)

	# return response status code
	if r.status_code != expected_status:
		r.raise_for_status() # anything but 200
		raise IOError("Got unexpected status code %s." % r.status_code)

# define how to run a test

def restart_fail2ban_service():
	# Log in over SSH to restart fail2ban.
	os.system("ssh %s@%s sudo service fail2ban restart"
		% (ssh_user, hostname))

def run_test(testfunc, args, count, within_time):
	# Run testfunc count times in within_time seconds (and actually
	# within a little less time so we're sure we're under the limit).

	import requests.exceptions

	restart_fail2ban_service()

	# Log.
	print(testfunc.__name__, " ".join(str(a) for a in args), "...")

	# Perform all tests within 4 requests per second.
	within_time = min(within_time, count/4)

	# Record the start time so we can know how to evenly space our
	# calls to testfunc.
	start_time = time.time()
	for i in range(count):
		print(i+1, end=" ", flush=True)

		# Run testfunc. It should succeed on each of these calls.
		try:
			testfunc(*args)
		except requests.exceptions.ConnectionError as e:
			print("Test machine prematurely blocked!", e)
			return False

		# Delay to evenly space the calls to testfunc within within_time.
		if i < count-1:
			delay = ((i+1) * within_time / (count-1)) - (time.time()-start_time)
			if delay > 0:
				time.sleep(delay)

	# Wait a moment for the block to be put into place.
	time.sleep(2)

	# The next call should fail.
	print("*", end=" ", flush=True)
	try:
		testfunc(*args)
	except requests.exceptions.ConnectionError as e:
		if "Connection refused" in str(e):
			# Success -- this one is supposed to be refused.
			print("blocked [OK]")
			return True # OK

	print("not blocked!")
	return False

######################################################################

# run tests

run_test(smtp_test, [], 20, 30)
run_test(imap_test, [], 20, 30)
run_test(http_test, ["/admin/me", 200], 20, 30)
run_test(http_test, ["/admin/munin/", 401], 20, 30)
run_test(http_test, ["/cloud/remote.php/caldav/calendars/user@domain/personal", 401], 20, 30)

# restart fail2ban so that this client machine is no longer blocked
restart_fail2ban_service()
