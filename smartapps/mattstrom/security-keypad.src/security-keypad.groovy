/**
 *  security-keypad
 *
 *  Copyright 2017 Matt Strom
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */

include 'asynchttp_v1';
 
definition(
    name: "Security Keypad",
    namespace: "mattstrom",
    author: "Matt Strom",
    description: "SmartApp counterpart to the SmartThings-Keypad web app.",
    category: "Safety & Security",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    oauth: [
        displayName: "Security Keypad",
        displayLink: "http://home.mattstrom.com"
    ]
)


preferences {
	section("Settings") {
    	input "securityCode", "string", title: "Security Code", required: true
    	input "countdown", "number", title: "Countdown (in seconds)", defaultValue: 30
        input "serverUrl", "string", title: "Server URL", defaultValue: "http://home.mattstrom.com:4567"
    }
    section("Voice Controlled Switch") {
    	input "voiceControlledSwitch", "capability.switch", title: "Voice Controlled Switch", multiple: false, required: true
    }
	section("Intrusion Detection Signal") {
        input "intrusionDetectors", "capability.switch", title: "Intrusion Detector", multiple: true, required: true
	}
    section("Devices to control") {
    	input "alarms", "capability.alarm", title: "Which alarms?", multiple: true, required: false
        input "lights", "capability.switch", title: "Which switches?", multiple: true, required: true
    }
    //section("Voice Control") {
    //	input "voice", "capability.audioNotification"
    //}
}

mappings {
	path("/status") {
    	action: [
        	GET: "onGetArmedStatus"
        ]
    }
    path("/arm") {
    	action: [
        	PUT: "onArmSystem"
        ]
    }
    path("/disarm") {
    	action: [
        	PUT: "onDisarmSystem"
        ]
    }
}

def installed() {
	log.debug "Installed with settings: ${settings}"

	initialize()
}

def updated() {
	log.debug "Updated with settings: ${settings}"

	unsubscribe()
	initialize()
}

def initialize() {
	// FIXME: Possible vulnerability. Resetting system disarms security.
	state.armed = false;
    
    subscribe(intrusionDetectors, 'switch.on', onIntrusion)
    subscribe(voiceControlledSwitch, 'switch.on', onVoiceControl)
    subscribe(voiceControlledSwitch, 'switch.off', onVoiceControl)
}

def onIntrusion(event) {
	log.debug("Intrusion Detected");
    
    asynchttp_v1.post(onAsyncResponse, [
    	uri: serverUrl,
        path: "/security/startCountdown",
        requestContentType: 'application/json',
        body: [
        	startTime: now(),
        	duration: countdown
        ]
    ]);
    
	runIn(countdown, onTimeElapsed);
}

def onAsyncResponse(response, data) {
	log.debug("Response: ${data}")
}

def onTimeElapsed(event) {
	log.debug("Time Elapsed");
	if (state.armed) {
    	lights.on();
        alarms?.both();
    }
    
    intrusionDetectors.off();
}

def onArmSystem(event) {
	armSystem();
}

def onGetArmedStatus() {
	return [
    	data: (state.armed) ? 'armed' : 'disarmed'
    ];
}

def onDisarmSystem() {
	def code = request.JSON?.securityCode
    disarmSystem(code)
}

def onVoiceControl(event) {
	log.debug("Event: ${event}")

	armSystem();
}

def armSystem() {
	log.debug("System Armed");
    state.armed = true;
    
    asynchttp_v1.put(onAsyncResponse, [
    	uri: serverUrl,
        path: "/security/status",
        requestContentType: 'application/json',
        body: [
        	status: 'armed'
        ]
    ]);
}

def disarmSystem(code) {
    if (securityCode == code) {
    	log.debug("Valid Code ${code}");
		log.debug("System Disarmed");
    
    	state.armed = false;
        alarms?.off();
        lights.off();
        
        asynchttp_v1.put(onAsyncResponse, [
            uri: serverUrl,
            path: "/security/status",
            requestContentType: 'application/json',
            body: [
                status: 'disarmed'
            ]
        ]);
        
        render(status: 200, data: "System Disarmed");
    } else {
    	log.debug("Invalid Code ${code}");
        httpError(403, "Invalid security code");
    }
}

// TODO: implement event handlers