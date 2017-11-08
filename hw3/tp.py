from selenium import webdriver
import time
import os

userid = '111491357'
passphrase = 'jay_*SUNY*SBU*_cs17'
try:
	url = "https://psns.cc.stonybrook.edu/psp/csprods/EMPLOYEE/CAMP/c/SA_LEARNER_SERVICES.SSR_SSENRL_CART.GBL?PORTALPARAM_PTCNAV=HC_SSR_SSENRL_CART_GBL&EOPP.SCNode=CAMP&EOPP.SCPortal=EMPLOYEE&EOPP.SCName=ADMN_SOLAR_SYSTEM&EOPP.SCLabel=Enrollment&EOPP.SCFName=HCCC_ENROLLMENT&EOPP.SCSecondary=true&EOPP.SCPTcname=PT_PTPP_SCFNAV_BASEPAGE_SCR&FolderPath=PORTAL_ROOT_OBJECT.CO_EMPLOYEE_SELF_SERVICE.SU_STUDENT_FOLDER.HCCC_ENROLLMENT.HC_SSR_SSENRL_CART_GBL&IsFolder=false"
	link_to_i_frame = 'https://psns.cc.stonybrook.edu/psc/csprods/EMPLOYEE/CAMP/c/SA_LEARNER_SERVICES.SSR_SSENRL_CART.GBL?PORTALPARAM_PTCNAV=HC_SSR_SSENRL_CART_GBL&amp;EOPP.SCNode=CAMP&amp;EOPP.SCPortal=EMPLYEE&amp;EOPP.SCName=ADMN_SOLAR_SYSTEM&amp;EOPP.SCLabel=Enrollment&amp;EOPP.SCFName=HCCC_ENROLLMENT&amp;EOPP.SCSecondary=true&amp;EOPP.SCPTcname=PT_PTPP_SCFNAV_BASEPAGE_SCR&amp;FolderPath=PORTAL_ROOT_OBJECT.CO_EMPLOYEE_SELF_SERVICE.SU_STUDENT_FOLDER.HCCC_ENROLLMENT.HC_SSR_SSENRL_CART_GBL&amp;IsFolder=false%27&amp;PortalActualURL=https%3a%2f%2fpsns.cc.stonybrook.edu%2fpsc%2fcsprods%2fEMPLOYEE%2fCAMP%2fc%2fSA_LEARNER_SERVICES.SSR_SSENRL_CART.GBL&amp;PortalContentURL=https%3a%2f%2fpsns.cc.stonybrook.edu%2fpsc%2fcsprods%2fEMPLOYEE%2fCAMP%2fc%2fSA_LEARNER_SERVICES.SSR_SSENRL_CART.GBL&amp;PortalContentProvider=CAMP&amp;PortalCRefLabel=Enrollment%3a%20%20Add%20Classes&amp;PortalRegistryName=EMPLOYEE&amp;PortalServletURI=https%3a%2f%2fpsns.cc.stonybrook.edu%2fpsp%2fcsprods%2f&amp;PortalURI=https%3a%2f%2fpsns.cc.stonybrook.edu%2fpsc%2fcsprods%2f&amp;PortalHostNode=CAMP&amp;NoCrumbs=yes&amp;PortalKeyStruct=yes'

	chauffeur = webdriver.Chrome(executable_path="./chromedriver")
	chauffeur.get(url)

	us = chauffeur.find_element_by_id("userid")
	us.send_keys(userid)

	pd = chauffeur.find_element_by_id("pwd")
	pd.send_keys(passphrase)

	sub = chauffeur.find_element_by_class_name("psloginbutton")
	sub.click()

	chauffeur.switch_to.frame("TargetContent")
	pd = chauffeur.find_element_by_id("SSR_DUMMY_RECV1$sels$2$$0")
	pd.click()

	pd = chauffeur.find_element_by_id("DERIVED_SSS_SCT_SSR_PB_GO")
	pd.click()

	time.sleep(2)

	while True:
		proc = chauffeur.find_element_by_id("DERIVED_REGFRM1_LINK_ADD_ENRL$82$")
		proc.click()
		time.sleep(4)

		try:
			fin_enroll = chauffeur.find_element_by_id("DERIVED_REGFRM1_SSR_PB_SUBMIT")
			fin_enroll.click()
			time.sleep(4)
		except Exception as e:
			print e
		
		add_another = chauffeur.find_element_by_id("DERIVED_REGFRM1_SSR_LINK_STARTOVER")
		add_another.click()
		time.sleep(4)


except Exception,e:
	print e
	chauffeur.quit()
	time.sleep(60)

	os.system("python tp.py")
