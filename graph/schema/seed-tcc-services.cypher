// Rootstock TCC Service Seed
// Pre-creates all known TCC_Permission nodes with canonical service identifiers
// and human-readable display names.
// Safe to run multiple times (MERGE is idempotent).

MERGE (t:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
SET t.display_name = 'Full Disk Access';

MERGE (t:TCC_Permission {service: 'kTCCServiceAccessibility'})
SET t.display_name = 'Accessibility';

MERGE (t:TCC_Permission {service: 'kTCCServiceScreenCapture'})
SET t.display_name = 'Screen Recording';

MERGE (t:TCC_Permission {service: 'kTCCServiceMicrophone'})
SET t.display_name = 'Microphone';

MERGE (t:TCC_Permission {service: 'kTCCServiceCamera'})
SET t.display_name = 'Camera';

MERGE (t:TCC_Permission {service: 'kTCCServiceAppleEvents'})
SET t.display_name = 'Automation';

MERGE (t:TCC_Permission {service: 'kTCCServiceListenEvent'})
SET t.display_name = 'Input Monitoring';

MERGE (t:TCC_Permission {service: 'kTCCServicePostEvent'})
SET t.display_name = 'Keyboard Event Injection';

MERGE (t:TCC_Permission {service: 'kTCCServiceSystemPolicyDesktopFolder'})
SET t.display_name = 'Desktop Folder';

MERGE (t:TCC_Permission {service: 'kTCCServiceSystemPolicyDocumentsFolder'})
SET t.display_name = 'Documents Folder';

MERGE (t:TCC_Permission {service: 'kTCCServiceSystemPolicyDownloadsFolder'})
SET t.display_name = 'Downloads Folder';

MERGE (t:TCC_Permission {service: 'kTCCServiceSystemPolicyRemovableVolumes'})
SET t.display_name = 'Removable Volumes';

MERGE (t:TCC_Permission {service: 'kTCCServiceSystemPolicyNetworkVolumes'})
SET t.display_name = 'Network Volumes';

MERGE (t:TCC_Permission {service: 'kTCCServiceEndpointSecurityClient'})
SET t.display_name = 'Endpoint Security';

MERGE (t:TCC_Permission {service: 'kTCCServiceLocation'})
SET t.display_name = 'Location Services';

MERGE (t:TCC_Permission {service: 'kTCCServicePhotos'})
SET t.display_name = 'Photos';

MERGE (t:TCC_Permission {service: 'kTCCServiceContacts'})
SET t.display_name = 'Contacts';

MERGE (t:TCC_Permission {service: 'kTCCServiceCalendar'})
SET t.display_name = 'Calendar';

MERGE (t:TCC_Permission {service: 'kTCCServiceReminders'})
SET t.display_name = 'Reminders';

MERGE (t:TCC_Permission {service: 'kTCCServiceAddressBook'})
SET t.display_name = 'Address Book';

MERGE (t:TCC_Permission {service: 'kTCCServiceSpeechRecognition'})
SET t.display_name = 'Speech Recognition';

MERGE (t:TCC_Permission {service: 'kTCCServiceBluetoothAlways'})
SET t.display_name = 'Bluetooth';

MERGE (t:TCC_Permission {service: 'kTCCServiceUserTracking'})
SET t.display_name = 'Tracking';

MERGE (t:TCC_Permission {service: 'kTCCServiceFocusStatus'})
SET t.display_name = 'Focus Status';
