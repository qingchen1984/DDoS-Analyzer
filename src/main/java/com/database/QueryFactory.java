/**
 * 
 */
package com.database;

/**
 * @author aavalos
 *
 */
public class QueryFactory {
	/**
	 * Gets the insert query for the given table name.
	 * 
	 * @param tableName Table name for the insert query.
	 * @return Insert string.
	 */
	public static String getInsertQueryForTable(String tableName) {
		return "INSERT INTO " + tableName 
				+ "(Timestamp,SrcAddress) "
    		+ "VALUES(?,?)";
	}
	
	/**
	 * Gets the insert query for the table that holds Country stats.
	 * 
	 * @param tableName Table name for the insert query.
	 * @return
	 */
	public static String getInsertCountryStatsQuery(String tableName) {
		return "INSERT INTO " + tableName 
				+ "(SrcAddress,packetCount,totalSeconds,rate,Country,City,FloodType) "
    		+ "VALUES(?,?,?,?,?,?,?)";
	}
	
	/**
	 * Gets the select query for the table that holds Country stats.
	 * 
	 * @param tableName Table name for the insert query.
	 * @return
	 */
	public static String getSelectCountryStatsQuery(String tableName, String floodTable) {
		return "SELECT "
				+ " Country,"
				+ " COUNT(*) AS numOfCountries,"
				+ " SUM(packetCount) AS packetCount,"
				+ " SUM(totalSeconds) AS totalSeconds"
				+ " FROM " + tableName 
				+ " WHERE FloodType='" + floodTable + "'"
				+ " GROUP BY Country";
	}
	
	/**
	 * Query to be used to get a list of DOS victims and the amount of attack packets.
	 * 
	 * @param tableName Table name where to get the list from.
	 * @param minPacket Lower bound of packets.
	 * @param minSecs Lower bound of seconds.
	 * @param rate Lower bound rate of attack (packets per second) for each source address.
	 * @return Query
	 */
	public static String getDosVictimsQuery(String tableName, int minPacket, int minSecs, int rate) {
		return "SELECT "
				+ "SrcAddress, "
				+ "packetCount, "
				+ "totalSeconds, "
				+ "rate "
				+ "FROM victims_" + tableName + " "
				+ "WHERE "
					+ "packetCount >= " + minPacket + " AND "
					+ "totalSeconds >= " + minSecs + " AND "
					+ "rate >= " + rate;
	}
	
	/**
	 * Query to be used to get a list of DOS victims and the amount of attack packets.
	 * 
	 * @param tableName Table name where to get the list from
	 * @return
	 */
	public static String getCreateAllDosVictimsQuery(String tableName) {
		return "CREATE TABLE victims_" + tableName + " AS SELECT "
				+ "SrcAddress, "
				+ "COUNT(*) AS packetCount, "
				+ "TIMESTAMPDIFF(SECOND, MIN(TIMESTAMP), MAX(TIMESTAMP)) AS totalSeconds, "
				+ "COUNT(*) / NULLIF(TIMESTAMPDIFF(SECOND, MIN(TIMESTAMP), MAX(TIMESTAMP)), 0) AS rate "
				+ "FROM " + tableName + " "
				+ "GROUP BY SrcAddress ";
	}
	
	/**
	 * Query to be used to get a list of attack rate (packets per second).
	 * 
	 * @param tableName Table name where to get the list from.
	 * @param rate Lower bound rate of attack (packets per second) for each source address.
	 * @return Query
	 */
	public static String getAttackRateQuery(String tableName, int minPacket, int minSecs, int rate) {
		return "SELECT "
				+ "TIMESTAMP, "
				+ "COUNT(*) AS packetPerSecond FROM ("
				+ "SELECT  FORMATDATETIME(TIMESTAMP, 'yyyy-MM-dd HH:mm:ss') as TIMESTAMP FROM " + tableName + " "
				+ "WHERE EXISTS ("
				+ getDosVictimsQuery(tableName, minPacket, minSecs, rate) + ")) AS stamp "
				+ "GROUP BY TIMESTAMP ORDER BY TIMESTAMP ASC";
	}
	
	/**
	 * Query to 
	 * @param tableName
	 * @return
	 */
	public static String getAttackRateForAddressQuery(String tableName) {
		return "SELECT "
				+ "TIMESTAMP, "
				+ "COUNT(*) AS packetPerSecond FROM ("
				+ "SELECT  FORMATDATETIME(TIMESTAMP, 'yyyy-MM-dd HH:mm:ss') as TIMESTAMP FROM " + tableName + " "
				+ "WHERE SrcAddress = ? ) AS stamp "
				+ "GROUP BY TIMESTAMP ORDER BY TIMESTAMP ASC";
	}
}
