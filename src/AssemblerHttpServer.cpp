#include "Assembler.hpp"
using namespace ChanZuckerberg;
using namespace Nanopore2;

#include <iomanip>
#include "iterator.hpp"


#define CZI_ADD_TO_FUNCTION_TABLE(name) httpServerData.functionTable[string("/") + #name ] = &Assembler::name



// Associate http keywords wth member functions.
void Assembler::fillServerFunctionTable()
{
    httpServerData.functionTable[""]        = &Assembler::exploreSummary;
    httpServerData.functionTable["/"]       = &Assembler::exploreSummary;
    httpServerData.functionTable["/index"]  = &Assembler::exploreSummary;
    CZI_ADD_TO_FUNCTION_TABLE(exploreSummary);

    CZI_ADD_TO_FUNCTION_TABLE(exploreReads);

}
#undef CZI_ADD_TO_FUNCTION_TABLE



void Assembler::processRequest(
    const vector<string>& request,
    ostream& html,
    const BrowserInformation&)
{
    // Look up the keyword to find the function that will process this request.
    // Note that the keyword includes the initial "/".
    const string& keyword = request.front();
    const auto it = httpServerData.functionTable.find(keyword);
    if(it == httpServerData.functionTable.end()) {
        writeHtmlBegin(html);
        html << "Unsupported keyword " << keyword;
        writeHtmlEnd(html);
        return;
    }


    // We found the keyword. Call the function that processes this keyword.
    // The processing function is only responsible for writing the html body.
    writeHtmlBegin(html);
    try {
        const auto function = it->second;
        (this->*function)(request, html);
    } catch(std::exception& e) {
        html << e.what();
    }
    writeHtmlEnd(html);
}



void Assembler::writeHtmlBegin(ostream& html) const
{
    html <<
        "\r\n"
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "<link rel=icon href=\"https://s0.wp.com/wp-content/themes/vip/czi/images/build/favicon.ico\" />"
        "<meta charset='UTF-8'>";
    writeStyle(html);
    writeMakeAllTablesSelectable(html);
    html <<
        "</head>"
        "<body onload='makeAllTablesSelectableByDoubleClick()'>";
    writeNavigation(html);
}



void Assembler::writeHtmlEnd(ostream& html) const
{
    html << "</body>";
    html << "</html>";
}




void Assembler::writeMakeAllTablesSelectable(ostream& html) const
{
    html << R"###(
<script>

// Make all tables selectable by double click.
// This must be called after all tables have
// already been created, so it can be called during onload.

// This function is called when the user double clicks on a table.
function selectElement(table)
{
    var selection = window.getSelection();
    selection.removeAllRanges();
    var range = document.createRange();
    range.selectNode(table);
    selection.addRange(range);
}

// Attach the above function to the double click event
// for all tables in the document.
// Also add to each table a title that displays a tooltip 
// explaining that the table can be selected via double click.
function makeAllTablesSelectableByDoubleClick()
{
    var allTables = document.getElementsByTagName("table");
    for (var i=0; i<allTables.length; i++) {
        var table = allTables[i];
        table.ondblclick = function() {selectElement(this);};
        table.setAttribute("title", 
        "Double click to select the entire table. You can then paste it into a spreadsheet.");
    }
}
</script>
    )###";
}



void Assembler::writeNavigation(ostream& html) const
{
    html << "<ul class=navigationMenu>";

    writeNavigation(html, "Run information", {
        {"Summary", "exploreSummary"},
        });
    writeNavigation(html, "Reads", {
        {"Reads", "exploreReads"},
        });

    html << "</ul>";
}



void Assembler::writeNavigation(
    ostream& html,
    const string& title,
    const vector<pair <string, string> >& items) const
{
    html <<
        "<li class=navigationMenuEntry>"
        "<div class=navigationButton>" << title << "</div>"
        "<div class=navigationItems>";

    for(const auto& item: items) {
        html << "<a class=navigationItem href=" << item.second << ">" << item.first << "</a>";
    }

    html << "</div></li>";

}



void Assembler::exploreSummary (
    const vector<string>& request,
    ostream& html)
{
    using std::setprecision;

    // Compute the total number of bases.
    uint64_t totalBaseCount = 0;
    for(ReadId readId=0; readId<reads.size(); readId++) {
        totalBaseCount += reads[readId].baseCount;
    }

    // Compute the number of k-mers used as markers.
    uint64_t markerKmerCount = 0;
    for(const auto& tableEntry: kmerTable) {
        if(tableEntry.isMarker) {
            ++ markerKmerCount;
        }
    }


    html <<
        "<h1>Run summary</h1>"
        "<table>"

        "<tr><td title='Total number of input reads'>Reads"
        "<td class=right>" << reads.size() <<

        "<tr><td title='Total number of reads on both strands"
        " (equal to twice the number of reads)'>Oriented reads"
        "<td class=right>" << 2*reads.size() <<

        "<tr><td title='Total number of input bases'>Bases"
        "<td class=right>" << totalBaseCount <<

        "<tr><td title='Average number of bases in a read'>Average read length"
        "<td class=right>" << int(0.5 + double(totalBaseCount) / double(reads.size())) <<

        "<tr><td title='The length of k-mers used as markers'>Marker length k"
        "<td class=right>" << assemblerInfo->k <<

        "<tr><td title='The total number of k-mers of length k'>Total k-mers"
        "<td class=right>" << kmerTable.size() <<

        "<tr><td title='The number of k-mers of length k used as markers'>Marker k-mers"
        "<td class=right>" << markerKmerCount <<

        "<tr><td title='The fraction of k-mers of length k used as markers'>Marker fraction"
        "<td class=right>" << setprecision(3) << double(markerKmerCount) / double(kmerTable.size()) <<

        "<tr><td title='Total number of markers on both strands'>Oriented markers"
        "<td class=right>" << markers.totalSize() <<

        "<tr><td title='The average number of markers per base'>Marker density"
        "<td class=right>" << setprecision(4) << double(markers.totalSize()) / (2.*double(totalBaseCount)) <<

        "<tr><td title='The average shift between consecutive markers in a read'>Marker average shift"
        "<td class=right>" << setprecision(4) << (2.*double(totalBaseCount)) / double(markers.totalSize())  <<

        "<tr><td title='The average gap between consecutive markers in a read'>Marker average gap"
        "<td class=right>" << setprecision(4) <<
        (2.*double(totalBaseCount)) / double(markers.totalSize()) - double(assemblerInfo->k) <<

        "<tr><td title='Number of candidate overlaps found by the MinHash algorithm'>Overlaps"
        "<td class=right>" << overlaps.size() <<

        "<tr><td title='Number of vertices in the global marker graph'>Marker graph vertices"
        "<td class=right>" << globalMarkerGraphVertices.size() <<

        "</table>";
}



void Assembler::exploreReads (
    const vector<string>& request,
    ostream& html)
{
    // Get the ReadId and Strand from the request.
    ReadId readId = 0;
    const bool readIdIsPresent = getParameterValue(request, "readId", readId);
    Strand strand = 0;
    const bool strandIsPresent = getParameterValue(request, "strand", strand);

    // Write the form.
    html <<
        "<form>"
        "<input type=submit value='Show read'> "
        "<input type=text name=readId title='Enter a read id between 0 and " << reads.size()-1 << "'>"
        " on strand "
        "<select name=strand>"
        "<option value=0>0 (+)</option>"
        "<option value=1>1 (-)</option>"
        "</select>"
        "</form>";

    // If the readId or strand are missing, stop here.
    if(!readIdIsPresent || !strandIsPresent) {
        return;
    }

    // Access the read.
    if(readId >= reads.size()) {
        html << "<p>Invalid read id.";
        return;
    }
    if(strand!=0 && strand!=1) {
        html << "<p>Invalid strand.";
        return;
    }
    const OrientedReadId orientedReadId(readId, strand);
    const auto readSequence = reads[readId];
    const auto readName = readNames[readId];



    // Page title.
    html << "<h1>Oriented read " << orientedReadId << "</h1>";

    // Read name.
    html << "<p>Read name on input: ";
    copy(readName.begin(), readName.end(), ostream_iterator<char>(html));

    // Read length.
    html << "<p>This read is " << readSequence.baseCount << " bases long.";

    // Read sequence.
    html << "<p><div style='font-family:monospace'>";
    html << "<br>";
    for(uint32_t i=0; i<readSequence.baseCount; i+=10) {
        const string label = to_string(i);
        html << label;
        for(size_t j=0; j<10-label.size(); j++) {
            html << "&nbsp;";
        }
    }
    html << "<br>";
    for(uint32_t i=0; i<readSequence.baseCount; i++) {
        if((i%10)==0) {
            html << "|";
        } else if((i%5)==0) {
            html << "+";
        } else {
            html << ".";
        }
    }
    html << "<br>";
    readSequence.write(html, strand==1);



    // Write the markers on k rows.
    const size_t k = assemblerInfo->k;
    const auto orientedReadMarkers = markers[orientedReadId.getValue()];
    for(size_t markerRow=0; markerRow<k; markerRow++) {
        html << "<br>";
        size_t position = 0;
        for(uint32_t ordinal=uint32_t(markerRow);
            ordinal<uint32_t(orientedReadMarkers.size()); ordinal+=uint32_t(k)) {
            const CompressedMarker& marker = orientedReadMarkers[ordinal];
            const Kmer kmer(marker.kmerId, k);
            while(position < marker.position) {
                html << "&nbsp;";
                ++position;
            }
            kmer.write(html, k);
            position += assemblerInfo->k;

        }
    }


    html << "</div>";
}

