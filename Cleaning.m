%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.


% Cleaning data sets:
% 1. Ordering all requests based on their time occurances
% 2. Duplicate request witch have all identical attributes have been
% reduced to just one item.
% 3. Change all filled data to lower case for improving perfromance in
% later analysis

clc
clear
close all
pause(2)

%% Import Data

[filename, pathname]=uigetfile({'*.*'},'Log file selector');
Path=[pathname filename];

load(Path)
Name=filename(1:length(filename)-4);
Name=[Name 'AndCleaned.mat'];
Name=[pathname '\' Name];
%load access_logConverted.mat

%% Define Duplicate Variable
%global IP HttpMethod File ErrorCode DataVolume Referrer UserAgent Duplicates
Duplicates=[];

%% Sorting
formatIn='dd/mm/yyyy:HH:MM:SS';
DateTime=datenum(DateTime,formatIn);
[DateTime,Order]=sort(DateTime,'ascend');

IP=lower(IP(Order));
HttpMethod=lower(HttpMethod(Order));
File=lower(File(Order));
ErrorCode=lower(ErrorCode(Order));
DataVolume=lower(DataVolume(Order));
Referrer=lower(Referrer(Order));
UserAgent=lower(UserAgent(Order));

%% Finding duplicates
PossibleDuplicates=DateTime(1:end-1)-DateTime(2:end);
PossibleDuplicates=find(PossibleDuplicates==0);
Range=PossibleDuplicates(1:end-1)-PossibleDuplicates(2:end);
Range=find(Range~=-1);

start=1;
for CheckR=1:numel(Range)
    Similar=PossibleDuplicates(start:Range(CheckR));%similar in Time
    Similar=[Similar; Similar(end)+1];
    [FileNew,Order]=sort(File(Similar));
    CheckF=1;
    while (CheckF<=numel(FileNew))
        SimilarF=Similar(Order(CheckF));
        for InerCheckF=CheckF+1:numel(FileNew)
            if(strcmp(FileNew(CheckF),FileNew(InerCheckF)))
                SimilarF=[SimilarF; Similar(Order(InerCheckF))];
                if(InerCheckF==numel(FileNew))
                    %Found more than two duplicates in time and File->go to next check
                    Duplicates=CheckDuplicatesErrorCode(SimilarF,ErrorCode,Referrer,DataVolume,IP,UserAgent,Duplicates);
                end
            elseif(numel(SimilarF)>1)
                %Found more than two duplicates in time and File->go to next check
                Duplicates=CheckDuplicatesErrorCode(SimilarF,ErrorCode,Referrer,DataVolume,IP,UserAgent,Duplicates);
                break;
            else
                break;
            end
        end
        CheckF=InerCheckF;
    end
    start=Range(CheckR)+1;
end

%% Removing duplicates

IP(Duplicates)=[];
DateTime(Duplicates)=[];
HttpMethod(Duplicates)=[];
File(Duplicates)=[];
ErrorCode(Duplicates)=[];
DataVolume(Duplicates)=[];
Referrer(Duplicates)=[];
UserAgent(Duplicates)=[];

%% Convert nan to zero for data volumes
Temp=find(isnan(str2double(DataVolume)));
DataVolume=str2double(DataVolume);
DataVolume(Temp)=0;

%clearvars Temp InerCheckF CheckF CheckR Duplicates formatIn Order PossibleDuplicates Range Similar SimilarF start pathname filename Path ans FileNew
save(Name,'IP','DateTime','HttpMethod','File','ErrorCode','DataVolume','Referrer','UserAgent')