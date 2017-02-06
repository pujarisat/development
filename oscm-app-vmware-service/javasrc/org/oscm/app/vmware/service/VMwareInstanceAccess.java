/*******************************************************************************
 *                                                                              
 *  Copyright FUJITSU LIMITED 2016                                           
 *                                                                                                                                 
 *  Creation Date: 2016/11/11                                                      
 *                                                                              
 *******************************************************************************/

package org.oscm.app.vmware.service;

import java.util.List;

import org.oscm.app.common.intf.InstanceAccess;
import org.oscm.app.common.intf.ServerInformation;
import org.oscm.app.v2_0.exceptions.APPlatformException;

/**
 * @author tateiwamext
 * 
 */
public class VMwareInstanceAccess implements InstanceAccess {

    private static final long serialVersionUID = 5685290474829749127L;

    @Override
    public List<? extends ServerInformation> getServerDetails(String instanceId,
            String subscriptionId, String organizationId)
            throws APPlatformException {
        return null;
    }

    @Override
    public String getAccessInfo(String instanceId, String subscriptionId,
            String organizationId) throws APPlatformException {
        return null;
    }

    @Override
    public String getMessage(String locale, String key, Object... arguments) {
        return null;
    }

}
