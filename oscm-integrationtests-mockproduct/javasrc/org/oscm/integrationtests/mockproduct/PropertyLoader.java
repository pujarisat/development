/**+++*****************************************************
 *
 * Copyright (c) FUJITSU Limited 2010
 * All rights reserved.
 *
 * Company:      FUJITSU Limited
 * Package name: com.fujitsu.fnst.bada.utils
 *
 **---****************************************************/

package org.oscm.integrationtests.mockproduct;

import java.util.Properties;

/**
 * Load properties from 'common.properties'
 * 
 * @author Wan Peng
 */
public class PropertyLoader {
    private final Properties prop;
    private static PropertyLoader PL_INSTANCE = null;

    private PropertyLoader() {
        prop = new Properties();
    }

    /**
     * Get a instance of PropertyLoader
     * 
     * @return Return a instance of PropertyLoader.
     */
    public static PropertyLoader getInstance() {
        if (PL_INSTANCE == null) {
            PL_INSTANCE = new PropertyLoader();
        }
        return PL_INSTANCE;
    }

    /**
     * Load property file.
     * 
     * @param file
     *            The property file will be loaded.
     * @return Return properties.
     */
    public Properties load(String file) {
        try {
            prop.load(Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream(file));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return prop;
    }
}
