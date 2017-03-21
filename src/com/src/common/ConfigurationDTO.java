package com.src.common;

import java.util.Arrays;
import java.util.List;

import org.joda.time.DateTime;

public class ConfigurationDTO {
	private String adapter;
	private String section;
	private String name;
	private String display_name;
	private int sequence;
	private String description;
	private String tool_tip;
	private String control_type;
	private String data_type;
	private String value;
	private String salt_value;
	private String upload_directory;
	private String upload_file_name;
	private String upload_file_type_URI;
	private String supported_file_formats;
	private int max_upload_file_size;
	private String supported_values;
	private String example_value;
	private boolean is_editable;
	private boolean display_in_UI;
	private boolean blank_values_allowed;
	private boolean restart_required;
	private DateTime date_time_created;
	private DateTime date_time_modified;
	private String last_updated_by_user;
	
	private static final String strString = "String";
	private static final String strInteger = "Integer";
	private static final String strBoolean = "Boolean";
	private static final String strCronSchedule = "CronSchedule";
	private static final String strFileUploadDataType = "FileUpload";
	private static final String strPassword = "Password";
	private static List<String> dataTypeValues = Arrays.asList(strString, strInteger, strBoolean, strCronSchedule, strFileUploadDataType, strPassword);
	
	private static final String strTextBox = "TextBox";
	private static final String strPasswordTextBox = "PasswordTextBox";
	private static final String strFileUpload = "FileUpload";
	private static final String strRadioToggle = "Radio/Toggle";
	private static final String strDropdown = "DropDown";
	private static List<String> controlTypeValues = Arrays.asList(strTextBox, strPasswordTextBox, strFileUpload, strRadioToggle, strDropdown);
	public String getAdapter() {
		return adapter;
	}
	public void setAdapter(String adapter) {
		this.adapter = adapter;
	}
	public String getSection() {
		return section;
	}
	public void setSection(String section) {
		this.section = section;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getDisplay_name() {
		return display_name;
	}
	public void setDisplay_name(String display_name) {
		this.display_name = display_name;
	}
	public int getSequence() {
		return sequence;
	}
	public void setSequence(int sequence) {
		this.sequence = sequence;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getTool_tip() {
		return tool_tip;
	}
	public void setTool_tip(String tool_tip) {
		this.tool_tip = tool_tip;
	}
	public String getControl_type() {
		return control_type;
	}
	public void setControl_type(String control_type) {
		if(controlTypeValues.contains(control_type)){
			this.control_type = control_type;
		}
	}
	public String getData_type() {
		return data_type;
	}
	public void setData_type(String data_type) {
		if(dataTypeValues.contains(data_type)){
			this.data_type = data_type;
		}
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	public String getSalt_Value() {
		return salt_value;
	}
	public void setSalt_Value(String salt_value) {
		this.salt_value = salt_value;
	}
	public String getUpload_directory() {
		return upload_directory;
	}
	public void setUpload_directory(String upload_directory) {
		this.upload_directory = upload_directory;
	}
	
	public String getUpload_File_Name() {
		return upload_file_name;
	}
	public void setUpload_File_Name(String upload_file_name) {
		this.upload_file_name = upload_file_name;
	}
	
	public String getUpload_File_Type_URI() {
		return upload_file_type_URI;
	}
	public void setUpload_File_Type_URI(String upload_file_type_URI) {
		this.upload_file_type_URI = upload_file_type_URI;
	}
	
	public String getSupported_file_formats() {
		return supported_file_formats;
	}
	public void setSupported_file_formats(String supported_file_formats) {
		this.supported_file_formats = supported_file_formats;
	}
	public int getMax_upload_file_size() {
		return max_upload_file_size;
	}
	public void setMax_upload_file_size(int max_upload_file_size) {
		this.max_upload_file_size = max_upload_file_size;
	}
	public String getSupported_values() {
		return supported_values;
	}
	public void setSupported_values(String supported_values) {
		this.supported_values = supported_values;
	}
	public String getExample_value() {
		return example_value;
	}
	public void setExample_value(String example_value) {
		this.example_value = example_value;
	}
	public boolean isIs_editable() {
		return is_editable;
	}
	public void setIs_editable(boolean is_editable) {
		this.is_editable = is_editable;
	}
	public boolean isDisplay_in_UI() {
		return display_in_UI;
	}
	public void setDisplay_in_UI(boolean display_in_UI) {
		this.display_in_UI = display_in_UI;
	}
	public boolean isBlank_values_allowed() {
		return blank_values_allowed;
	}
	public void setBlank_values_allowed(boolean blank_values_allowed) {
		this.blank_values_allowed = blank_values_allowed;
	}
	public boolean isRestart_required() {
		return restart_required;
	}
	public void setRestart_required(boolean restart_required) {
		this.restart_required = restart_required;
	}
	public DateTime getDate_time_created() {
		return date_time_created;
	}
	public void setDate_time_created(DateTime date_time_created) {
		this.date_time_created = date_time_created;
	}
	public DateTime getDate_time_modified() {
		return date_time_modified;
	}
	public void setDate_time_modified(DateTime date_time_modified) {
		this.date_time_modified = date_time_modified;
	}
	public String getLast_updated_by_user() {
		return last_updated_by_user;
	}
	public void setLast_updated_by_user(String last_updated_by_user) {
		this.last_updated_by_user = last_updated_by_user;
	}
	public static List<String> getDataTypeValues() {
		return dataTypeValues;
	}
	public static void setDataTypeValues(List<String> dataTypeValues) {
		ConfigurationDTO.dataTypeValues = dataTypeValues;
	}
	public static List<String> getControlTypeValues() {
		return controlTypeValues;
	}
	public static void setControlTypeValues(List<String> controlTypeValues) {
		ConfigurationDTO.controlTypeValues = controlTypeValues;
	}
}