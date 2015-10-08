/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2015 
 *******************************************************************************/

//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 in JDK 6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2013.03.05 at 01:29:11 PM CET 
//


package org.oscm.billingservice.business.model.billingresult;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Parameter option.
 * 
 * <p>Java class for ParameterOptionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ParameterOptionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="PeriodFee" type="{}PeriodFeeType"/>
 *         &lt;element name="UserAssignmentCosts" type="{}ParametersUserAssignmentCostsType"/>
 *         &lt;element name="OptionCosts" type="{}NormalizedCostsType"/>
 *       &lt;/sequence>
 *       &lt;attribute name="id" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ParameterOptionType", propOrder = {
    "periodFee",
    "userAssignmentCosts",
    "optionCosts"
})
public class ParameterOptionType {

    @XmlElement(name = "PeriodFee", required = true)
    protected PeriodFeeType periodFee;
    @XmlElement(name = "UserAssignmentCosts", required = true)
    protected ParametersUserAssignmentCostsType userAssignmentCosts;
    @XmlElement(name = "OptionCosts", required = true)
    protected NormalizedCostsType optionCosts;
    @XmlAttribute(required = true)
    protected String id;

    /**
     * Gets the value of the periodFee property.
     * 
     * @return
     *     possible object is
     *     {@link PeriodFeeType }
     *     
     */
    public PeriodFeeType getPeriodFee() {
        return periodFee;
    }

    /**
     * Sets the value of the periodFee property.
     * 
     * @param value
     *     allowed object is
     *     {@link PeriodFeeType }
     *     
     */
    public void setPeriodFee(PeriodFeeType value) {
        this.periodFee = value;
    }

    /**
     * Gets the value of the userAssignmentCosts property.
     * 
     * @return
     *     possible object is
     *     {@link ParametersUserAssignmentCostsType }
     *     
     */
    public ParametersUserAssignmentCostsType getUserAssignmentCosts() {
        return userAssignmentCosts;
    }

    /**
     * Sets the value of the userAssignmentCosts property.
     * 
     * @param value
     *     allowed object is
     *     {@link ParametersUserAssignmentCostsType }
     *     
     */
    public void setUserAssignmentCosts(ParametersUserAssignmentCostsType value) {
        this.userAssignmentCosts = value;
    }

    /**
     * Gets the value of the optionCosts property.
     * 
     * @return
     *     possible object is
     *     {@link NormalizedCostsType }
     *     
     */
    public NormalizedCostsType getOptionCosts() {
        return optionCosts;
    }

    /**
     * Sets the value of the optionCosts property.
     * 
     * @param value
     *     allowed object is
     *     {@link NormalizedCostsType }
     *     
     */
    public void setOptionCosts(NormalizedCostsType value) {
        this.optionCosts = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

}