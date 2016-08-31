/*******************************************************************************
 *
 *  Copyright FUJITSU LIMITED 2016
 *
 *  Creation Date: 18.07.2012
 *
 *******************************************************************************/
package org.oscm.internal.tenant;

import javax.ejb.Remote;
import java.util.List;

@Remote
public interface ManageTenantService {
    public List<POTenant> getAllTenants();
}