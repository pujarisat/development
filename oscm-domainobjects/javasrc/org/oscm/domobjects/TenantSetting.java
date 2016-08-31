/*******************************************************************************
 *
 *  Copyright FUJITSU LIMITED 2016
 *
 *  Author: Paulina Badziak
 *
 *  Creation Date: 30.08.2016
 *
 *  Completion Time: 30.08.2016
 *
 *******************************************************************************/
package org.oscm.domobjects;

import org.oscm.domobjects.annotations.BusinessKey;
import org.oscm.internal.types.enumtypes.IdpSettingType;

import javax.persistence.*;


@Entity
@Table(uniqueConstraints = @UniqueConstraint(columnNames = {
    "tenant_tkey", "name" }))
@BusinessKey(attributes = { "tenant", "name" })
public class TenantSetting extends DomainObjectWithVersioning<TenantSettingData> {

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_tkey")
    private Tenant tenant;

    public TenantSetting() {
        dataContainer = new TenantSettingData();
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public IdpSettingType getName() {
        return dataContainer.getName();
    }

    public String getValue() {
        return dataContainer.getValue();
    }
}