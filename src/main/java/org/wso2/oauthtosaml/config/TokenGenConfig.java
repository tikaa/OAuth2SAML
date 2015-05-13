/*
* Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.oauthtosaml.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.utils.CarbonUtils;

public class TokenGenConfig {

    private static final Log log = LogFactory.getLog(TokenGenConfig.class);
    
    private static final String CONFIG_FILE = "oauth-saml-token-config.properties";
    
    private boolean cacheEnabled = false;
    
    private static TokenGenConfig instance;
    
    private TokenGenConfig(){
        
        readConfiguration();
    }
    
    public static TokenGenConfig getInstance() {
        if(instance == null) {
            instance = new TokenGenConfig();
        }
        return instance;
    }
    
    public void readConfiguration() {

        String configurationFilePath = CarbonUtils.getCarbonConfigDirPath() + File.separator +
                "security" + File.separator + CONFIG_FILE;
        FileInputStream fileInputStream = null;
        Properties props = new Properties();

        try {
            fileInputStream = new FileInputStream(new File(configurationFilePath));
            props = new Properties();
            props.load(fileInputStream);

        } catch (FileNotFoundException e) {
            log.error("Unable to find the configuration file : " + CONFIG_FILE);
        } catch (IOException e) {
            log.error("Error reading the configuration file : " + CONFIG_FILE);
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException e) {
                log.error("Error closing the configuration file : " + CONFIG_FILE);
            }
        }
        
        String cacheEnabled = props.getProperty("enable.token.caching");
        if (cacheEnabled != null) {
            this.cacheEnabled = Boolean.parseBoolean(cacheEnabled.trim());
        }
    }

    public boolean isCacheEnabled() {
        return cacheEnabled;
    }
    
}
