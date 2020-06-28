// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#pragma once

#include <string_view>

#include "../Val.h"
#include "../Tag.h"
#include "../EventHandler.h"
#include "../plugin/ComponentManager.h"

#include "Component.h"
#include "WriterBackend.h"

namespace broker { struct endpoint_info; }
class SerializationFormat;
class RotationTimer;

namespace logging {

class WriterFrontend;
class RotationFinishedMessage;

/**
 * Singleton class for managing log streams.
 */
class Manager : public plugin::ComponentManager<Tag, Component> {
public:

	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Called after scripts are parsed; obtains values of customizable options.
	 */
	void InitPostScript();

	/**
	 * Calls the Log::rotation_format_func script function, tries to create
	 * any directories (failure to falls back to using working dir for
	 * rotation) and returns the formatted rotation path string that
	 * will be sent along to writer threads to perform the actual rotation.
	 * @param rotation_info  The fields of a Log::RotationFmtInfo record
	 *                       to create and pass to Log::rotation_format_func.
	 */
	std::string FormatRotationPath(zeek::EnumValPtr writer,
	                               std::string_view path, double open,
	                               double close, bool terminating,
	                               zeek::FuncPtr postprocesor);

	/**
	 * Creates a new log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param stream A record of script type \c Log::Stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool CreateStream(zeek::EnumVal* id, zeek::RecordVal* stream);

	/**
	 * Remove a log stream, stopping all threads.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveStream(zeek::EnumVal* id);

	/**
	 * Enables a log log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool EnableStream(zeek::EnumVal* id);

	/**
	 * Disables a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool DisableStream(zeek::EnumVal* id);

	/**
	 * Adds a filter to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param filter A record of script type \c Log::Filter.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool AddFilter(zeek::EnumVal* id, zeek::RecordVal* filter);

	/**
	 * Removes a filter from a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param name The name of the filter to remove.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveFilter(zeek::EnumVal* id, zeek::StringVal* name);

	/**
	 * Removes a filter from a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param name The name of the filter to remove.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveFilter(zeek::EnumVal* id, const std::string& name);

	/**
	 * Write a record to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param colums A record of the type defined for the stream's
	 * columns.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Write(zeek::EnumVal* id, zeek::RecordVal* columns);

	/**
	 * Create a new log writer frontend. This is exposed so that the
	 * communication system can recreate remote log streams locally.
	 *
	 * @param id The enum value corresponding to the log stream.
	 *
	 * @param writer The enum value corresponding to the desired log writer.
	 *
	 * @param info A fully initialized object defining the
	 * characteristics of the backend writer instance. The method takes
	 * ownership of this.
	 *
	 * @param num_fields The number of log fields to write.
	 *
	 * @param vals An array of log fields to write, of size num_fields.
	 * The method takes ownership of the array.
	 *
	 * @return Returns true if the writer was successfully created.
	 */
	bool CreateWriterForRemoteLog(zeek::EnumVal* id, zeek::EnumVal* writer, WriterBackend::WriterInfo* info,
	                              int num_fields, const threading::Field* const* fields);

	/**
	 * Writes out log entries that have already passed through all
	 * filters (and have raised any events). This is meant called for logs
	 * received already processed from remote.
	 *
	 * @param stream The enum value corresponding to the log stream.
	 *
	 * @param writer The enum value corresponding to the desired log writer.
	 *
	 * @param path The path of the target log stream to write to.
	 *
	 * @param num_fields The number of log values to write.
	 *
	 * @param vals An array of log values to write, of size num_fields.
	 * The method takes ownership of the array.
	 */
	bool WriteFromRemote(zeek::EnumVal* stream, zeek::EnumVal* writer, const std::string& path,
	                     int num_fields, threading::Value** vals);

	/**
	 * Announces all instantiated writers to a given Broker peer.
	 */
	void SendAllWritersTo(const broker::endpoint_info& ei);

	/**
	 * Sets log streams buffering state. This adjusts all associated
	 * writers to the new state.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param enabled False to disable buffering (default is enabled).
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool SetBuf(zeek::EnumVal* id, bool enabled);

	/**
	 * Flushes a log stream. This flushed all associated writers.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Flush(zeek::EnumVal* id);

	/**
	 * Signals the manager to shutdown at Bro's termination.
	 */
	void Terminate();

	/**
	 * Enable remote logs for a given stream.
	 * @param stream_id the stream to enable remote logs for.
	 * @return true if remote logs are enabled.
	 */
	bool EnableRemoteLogs(zeek::EnumVal* stream_id);

	/**
	 * Disable remote logs for a given stream.
	 * @param stream_id the stream to disable remote logs for.
	 * @return true if remote logs are disabled.
	 */
	bool DisableRemoteLogs(zeek::EnumVal* stream_id);

	/**
	 * @return true if remote logs are enabled for a given stream.
	 */
	bool RemoteLogsAreEnabled(zeek::EnumVal* stream_id);

	/**
	 * @return the type which corresponds to the columns in a log entry for
	 * a given log stream.
	 */
	zeek::RecordType* StreamColumns(zeek::EnumVal* stream_id);

protected:
	friend class WriterFrontend;
	friend class RotationFinishedMessage;
	friend class RotationFailedMessage;
	friend class ::RotationTimer;

	// Instantiates a new WriterBackend of the given type (note that
	// doing so creates a new thread!).
	WriterBackend* CreateBackend(WriterFrontend* frontend, zeek::EnumVal* tag);

	//// Function also used by the RemoteSerializer.

	// Takes ownership of fields and info.
	WriterFrontend* CreateWriter(zeek::EnumVal* id, zeek::EnumVal* writer, WriterBackend::WriterInfo* info,
	                             int num_fields, const threading::Field* const* fields,
	                             bool local, bool remote, bool from_remote,
	                             const std::string& instantiating_filter="");

	// Signals that a file has been rotated.
	bool FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name,
	                      double open, double close, bool success, bool terminating);

	// Deletes the values as passed into Write().
	void DeleteVals(int num_fields, threading::Value** vals);

private:
	struct Filter;
	struct Stream;
	struct WriterInfo;

	bool TraverseRecord(Stream* stream, Filter* filter, zeek::RecordType* rt,
	                    zeek::TableVal* include, zeek::TableVal* exclude,
	                    const std::string& path, const std::list<int>& indices);

	threading::Value** RecordToFilterVals(Stream* stream, Filter* filter,
	                                      zeek::RecordVal* columns);

	threading::Value* ValToLogVal(zeek::Val* val, zeek::Type* ty = nullptr);
	Stream* FindStream(zeek::EnumVal* id);
	void RemoveDisabledWriters(Stream* stream);
	void InstallRotationTimer(WriterInfo* winfo);
	void Rotate(WriterInfo* info);
	WriterInfo* FindWriter(WriterFrontend* writer);
	bool CompareFields(const Filter* filter, const WriterFrontend* writer);
	bool CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter);

	std::vector<Stream *> streams;	// Indexed by stream enum.
	int rotations_pending;	// Number of rotations not yet finished.
	zeek::FuncPtr rotation_format_func;
};

}

extern logging::Manager* log_mgr;
