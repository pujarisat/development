/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2016 
 *******************************************************************************/

package org.oscm.db;

import java.net.URL;
import java.sql.Connection;
import java.sql.SQLException;

import org.dbunit.database.DatabaseConnection;
import org.dbunit.dataset.IDataSet;
import org.dbunit.dataset.ReplacementDataSet;
import org.dbunit.dataset.xml.FlatXmlDataSetBuilder;
import org.dbunit.operation.DatabaseOperation;
import org.oscm.setup.DatabaseVersionInfo;
import org.oscm.test.db.ITestDB;
import org.oscm.test.ejb.TestDataSources;

public class TestDatabase {
    private static final ITestDB TESTDATABASE = TestDataSources
            .get("oscm-domainobjects");

    private final DatabaseVersionInfo fromVersion = new DatabaseVersionInfo(1,
            0, 16);
    private final DatabaseVersionInfo toVersion = new DatabaseVersionInfo(2, 0,
            22);

    private static final DatabaseVersionInfo MAX_VERSION = new DatabaseVersionInfo(
            Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);

    public void initDatabase() throws Exception {
        System.out.println("Start database initialization...");
        TESTDATABASE.purgeSchema();
        TESTDATABASE.loadSchema(fromVersion);
        TESTDATABASE.clearBusinessData();
        TESTDATABASE.loadSchema(toVersion);
        System.out.println("Database initialization finished");
    }

    public void insertData(URL dataSetUrl) throws Exception {
        System.out.println("Insert test data.");
        final IDataSet dataSet = loadDataSet(dataSetUrl);
        final DatabaseConnection connection = new DatabaseConnection(
                getDBconnection());
        DatabaseOperation.INSERT.execute(connection, dataSet);
    }

    public void clean() throws Exception {
        System.out.println("Clearn test data");
        TESTDATABASE.clearBusinessData();
    }

    public void close() throws Exception {
        System.out.println("Close database connection");
        TESTDATABASE.getDataSource().getConnection().close();
    }

    public Connection getDBconnection() throws SQLException {
        return TESTDATABASE.getDataSource().getConnection();
    }

    private IDataSet loadDataSet(URL source) throws Exception {
        final ReplacementDataSet set = new ReplacementDataSet(
                new FlatXmlDataSetBuilder().build(source));
        set.addReplacementObject("[NULL]", null);
        return set;
    }

    /**
     * The schema must be changed to the latest version for follow up test
     * cases.
     * 
     * @throws Exception
     */
    public void updateDBSchemaToLatestVersion() throws Exception {
        TESTDATABASE.purgeSchema();
        TESTDATABASE.loadSchema(MAX_VERSION);
    }

}
